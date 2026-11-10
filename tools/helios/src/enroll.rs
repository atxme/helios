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

use aether::certificates::encoding::DerCertificate;
use aether::key_negotiation::{decode_request_file, EnrollmentRequest, PqCertificate};
use anyhow::{Context, Result};
use base64::Engine as _;

use orion_core::enrollment_draft::{
    build_draft, check_leaves, resolve_negotiation_endpoint, Admission, DraftInput, GatewayMaterial,
};

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

/// Reads the material from the two public certificates on disk.
///
/// The PQ certificate carries the subject **and** the WireGuard key it is
/// pinned to, so the operator has nothing to retype: everything the profile
/// needs is inside the file, and verifying it here means a mistyped copy is
/// caught now rather than as a refused negotiation later.
fn offline_material(inputs: &OfflineInputs) -> Result<GatewayMaterial> {
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

pub async fn document(
    client: &reqwest::Client,
    base: &str,
    options: DocumentOptions,
) -> Result<()> {
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
    let draft = build_draft(DraftInput {
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

/// The gateway's material and the admission of a client it already holds.
///
/// One copy of this logic, shared with Orion: `orion_core::gateway_admin`.
async fn online_material(
    client: &reqwest::Client,
    base: &str,
    client_key: &str,
) -> Result<(GatewayMaterial, Admission)> {
    orion_core::gateway_admin::gateway_material(client, base, client_key)
        .await
        .map_err(anyhow::Error::from)
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
    use aether::certificates::encoding::{
        Fingerprint, Id16, MlDsa87PublicKey, MlDsa87Signature, WireGuardKey,
    };
    use aether::key_negotiation::{
        generate_ml_dsa_87_keypair, ENROLLMENT_FORMAT_VERSION, ENROLLMENT_PROTOCOL_VERSION,
    };

    /// A request to name in the command; the draft itself is tested in
    /// `orion-core`.
    fn request() -> EnrollmentRequest {
        let (_, client_ml_dsa) = generate_ml_dsa_87_keypair().unwrap();
        let client_wg = aether::wg::generate_keypair().unwrap();
        let csr = aether::certificates::x509::client_rotation_csr("poste-windows").unwrap();
        EnrollmentRequest {
            format_version: ENROLLMENT_FORMAT_VERSION,
            protocol_version: ENROLLMENT_PROTOCOL_VERSION,
            invitation_id: Id16::new([1; 16]).unwrap(),
            invitation_fingerprint: Fingerprint::from_bytes([2; 32]),
            request_id: Id16::new([3; 16]).unwrap(),
            timestamp_unix: 1,
            requested_name: "poste-windows".into(),
            client_wg_public_key: WireGuardKey::parse(&client_wg.public_key).unwrap(),
            tls_csr: csr.csr,
            client_ml_dsa_87_public_key: MlDsa87PublicKey::new(client_ml_dsa).unwrap(),
            wireguard_proof: [0; 32],
            client_signature: MlDsa87Signature::placeholder(),
        }
    }

    #[test]
    fn the_suggested_sign_command_never_carries_the_client_chosen_name() {
        let mut request = request();
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
    fn shell_word_quotes_empty_whitespace_and_embedded_quotes_safely() {
        assert_eq!(shell_word(""), "''");
        assert_eq!(shell_word("plain-1/path"), "plain-1/path");
        assert_eq!(shell_word("a b"), "'a b'");
        assert_eq!(shell_word("a'b"), "'a'\\''b'");
        assert_eq!(shell_word("$(touch marker)"), "'$(touch marker)'");
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

    fn transit_utf16(text: &str, little_endian: bool) -> Vec<u8> {
        let mut bytes = if little_endian {
            vec![0xFF, 0xFE]
        } else {
            vec![0xFE, 0xFF]
        };
        for unit in text.encode_utf16() {
            let encoded = if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            };
            bytes.extend_from_slice(&encoded);
        }
        bytes
    }

    #[test]
    fn read_request_accepts_transit_utf16_and_preserves_the_request() {
        use aether::key_negotiation::encode_request_file;

        let expected = request();
        let text = encode_request_file(&expected);
        let directory = tempfile::tempdir().expect("temporary request directory");

        for (name, little_endian) in [("request-le", true), ("request-be", false)] {
            let path = directory.path().join(name);
            std::fs::write(&path, transit_utf16(&text, little_endian))
                .expect("write UTF-16 request");

            let actual = read_request(&path).expect("read UTF-16 request");
            assert_eq!(actual.fingerprint(), expected.fingerprint(), "{name}");
            assert_eq!(actual.request_id, expected.request_id, "{name}");
        }
    }

    #[test]
    fn read_request_names_a_missing_file() {
        let directory = tempfile::tempdir().expect("temporary request directory");
        let path = directory.path().join("absent.helios-request");

        let error = read_request(&path).expect_err("missing request must fail");
        let message = format!("{error:#}");
        assert!(message.contains("reading"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
    }

    #[test]
    fn read_request_rejects_invalid_utf8_and_truncated_utf16_with_path_context() {
        let directory = tempfile::tempdir().expect("temporary request directory");
        for (name, bytes) in [
            ("invalid-utf8", vec![0xC3]),
            ("truncated-utf16", vec![0xFF, 0xFE, 0x41]),
        ] {
            let path = directory.path().join(name);
            std::fs::write(&path, bytes).expect("write malformed request");

            let error = read_request(&path).expect_err("malformed text must fail");
            let message = format!("{error:#}");
            assert!(message.contains("not readable text"), "{message}");
            assert!(message.contains(&path.display().to_string()), "{message}");
        }
    }

    #[test]
    fn read_request_rejects_json_that_is_not_a_request_envelope() {
        let directory = tempfile::tempdir().expect("temporary request directory");
        let path = directory.path().join("wrong-format.helios-request");
        std::fs::write(&path, br#"{"format":"not-a-helios-request","request":{}}"#)
            .expect("write wrong envelope");

        let error = read_request(&path).expect_err("wrong request envelope must fail");
        let message = format!("{error:#}");
        assert!(message.contains("not an enrollment request"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
    }

    #[test]
    fn read_file_names_the_missing_path() {
        let directory = tempfile::tempdir().expect("temporary input directory");
        let path = directory.path().join("absent.bin");

        let error = read_file(&path).expect_err("missing file must fail");
        let message = format!("{error:#}");
        assert!(message.contains("reading"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
    }

    #[test]
    fn read_trust_material_reports_missing_and_malformed_files_with_context() {
        let directory = tempfile::tempdir().expect("temporary trust directory");
        let missing = directory.path().join("absent-trust.json");

        let error = read_trust_material(&missing).expect_err("missing trust file must fail");
        let message = format!("{error:#}");
        assert!(message.contains("reading the trust block"), "{message}");
        assert!(
            message.contains(&missing.display().to_string()),
            "{message}"
        );

        let malformed = directory.path().join("malformed-trust.json");
        std::fs::write(&malformed, b"{not-json").expect("write malformed trust block");
        let error = read_trust_material(&malformed).expect_err("malformed trust JSON must fail");
        let message = format!("{error:#}");
        assert!(message.contains("is not a trust block"), "{message}");
        assert!(
            message.contains(&malformed.display().to_string()),
            "{message}"
        );
        assert!(message.contains("show-trust-enrolment"), "{message}");
    }

    #[test]
    fn read_trust_material_validates_decoded_fields_before_returning() {
        let directory = tempfile::tempdir().expect("temporary trust directory");
        let path = directory.path().join("invalid-trust.json");
        let trust = orion_core::TrustMaterial {
            trust_domain_id: "not-a-domain-id".into(),
            ca_epoch: 1,
            ca_pq_public_key: String::new(),
            ca_tls_epoch: 1,
            client_tls_ca_der: String::new(),
            client_generation: 1,
            active_gateway_identity_epoch: 1,
            gateway_decision_epoch: 1,
            astra_authority_url: "https://astra.example".into(),
            webauthn_rp_id: "astra.example".into(),
            astra_policy_fingerprint: String::new(),
            credential_registry_epoch: 1,
            astra_credential_bindings: Vec::new(),
            astra_service_key_epoch: 1,
            astra_service_public_key: String::new(),
        };
        std::fs::write(&path, serde_json::to_vec(&trust).expect("trust JSON"))
            .expect("write invalid trust block");

        let error = read_trust_material(&path).expect_err("invalid trust fields must fail");
        let message = format!("{error:#}");
        assert!(message.contains("trust block"), "{message}");
        assert!(message.contains("unusable"), "{message}");
        assert!(message.contains(&path.display().to_string()), "{message}");
    }

    #[test]
    fn offline_material_names_missing_gateway_certificate_files() {
        let directory = tempfile::tempdir().expect("temporary certificate directory");
        let der_path = directory.path().join("gateway.der");
        let pq_path = directory.path().join("gateway-pq.json");
        let inputs = |gateway_certificate: &std::path::Path,
                      gateway_pq_certificate: &std::path::Path| {
            OfflineInputs {
                gateway_certificate: gateway_certificate.to_path_buf(),
                gateway_pq_certificate: gateway_pq_certificate.to_path_buf(),
                address: "100.64.1.2/32".into(),
                address_v6: None,
                heliosd_url: None,
                trust_material: None,
            }
        };

        let der_error = offline_material(&inputs(&der_path, &pq_path))
            .err()
            .expect("missing DER file must fail first");
        let der_message = format!("{der_error:#}");
        assert!(
            der_message.contains("reading the gateway certificate"),
            "{der_message}"
        );
        assert!(
            der_message.contains(&der_path.display().to_string()),
            "{der_message}"
        );

        std::fs::write(&der_path, [0x30, 0x01]).expect("write DER fixture");
        let pq_error = offline_material(&inputs(&der_path, &pq_path))
            .err()
            .expect("missing PQ certificate file must fail");
        let pq_message = format!("{pq_error:#}");
        assert!(
            pq_message.contains("reading the gateway PQ certificate"),
            "{pq_message}"
        );
        assert!(
            pq_message.contains(&pq_path.display().to_string()),
            "{pq_message}"
        );
    }

    #[test]
    fn offline_material_rejects_a_pq_certificate_that_cannot_be_fingerprinted() {
        use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
        use base64::Engine as _;

        let directory = tempfile::tempdir().expect("temporary certificate directory");
        let der_path = directory.path().join("gateway.der");
        let pq_path = directory.path().join("gateway-pq.json");
        std::fs::write(&der_path, [0x30, 0x01]).expect("write DER fixture");

        let certificate = PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: [5; aether::key_negotiation::KEY_NEGOTIATION_NONCE_LEN],
            subject: "vpn.example.test".into(),
            issuer: "test CA".into(),
            role: PqCertificateRole::Gateway,
            wireguard_public_key: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=".into(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD
                .encode(vec![4; aether::key_negotiation::ML_DSA_87_PUBLIC_KEY_LEN]),
            not_before_unix: 1,
            not_after_unix: 2,
            // Fingerprinting requires a canonical base64 signature of the protocol length.
            ml_dsa_87_signature: "not-base64".into(),
        };
        std::fs::write(
            &pq_path,
            serde_json::to_vec(&certificate).expect("certificate JSON"),
        )
        .expect("write malformed signature fixture");
        let inputs = OfflineInputs {
            gateway_certificate: der_path,
            gateway_pq_certificate: pq_path,
            address: "100.64.1.2/32".into(),
            address_v6: None,
            heliosd_url: None,
            trust_material: None,
        };

        let error = offline_material(&inputs)
            .err()
            .expect("invalid fingerprint input must fail");
        let message = format!("{error:#}");
        assert!(message.contains("PQ certificate is invalid"), "{message}");
        assert!(!message.contains("not-base64"), "{message}");
    }

    #[tokio::test]
    async fn invalid_client_certificate_is_rejected_before_contacting_the_gateway() {
        let directory = tempfile::tempdir().expect("temporary enrollment directory");
        let request_path = directory.path().join("request.helios-request");
        let tls = directory.path().join("client.der");
        let pq = directory.path().join("client-pq.json");
        let output = directory.path().join("draft.orion");
        std::fs::write(
            &request_path,
            aether::key_negotiation::encode_request_file(&request()),
        )
        .expect("request");
        std::fs::write(&tls, []).expect("empty TLS certificate");
        std::fs::write(&pq, b"not JSON").expect("bad PQ certificate");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("gateway listener");
        let base = format!("http://{}", listener.local_addr().unwrap());
        let options = || DocumentOptions {
            request: request_path.clone(),
            tls_certificate: tls.clone(),
            pq_certificate: pq.clone(),
            endpoint: "vpn.example:51820".into(),
            negotiation_endpoint: None,
            allowed_ips: None,
            ssh_target: None,
            output: output.clone(),
            offline: None,
        };
        let client = reqwest::Client::new();
        let error = document(&client, &base, options())
            .await
            .expect_err("empty TLS certificate");
        assert!(format!("{error:#}").contains("not a DER certificate"));
        assert!(!output.exists());
        std::fs::write(&tls, [0x30, 0x01]).expect("bounded TLS fixture");
        let error = document(&client, &base, options())
            .await
            .expect_err("malformed PQ certificate");
        assert!(format!("{error:#}").contains("not a PQ certificate"));
        assert!(!output.exists());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "invalid local inputs must not contact the gateway"
        );
    }
}
