//! Operator tooling for key-negotiation certificates and protocol probes.

use std::{
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
};

use aether::key_negotiation::{
    generate_ml_dsa_65_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
    ProtectionMode, PQ_CERTIFICATE_VERSION,
};
use anyhow::{Context, Result};
use base64::Engine as _;
use clap::{Subcommand, ValueEnum};
use orion_core::key_negotiation::KeyNegotiationClient;
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose,
};
use rustls::pki_types::CertificateDer;
use zeroize::Zeroizing;

const CA_CERTIFICATE_FILE: &str = "orion-client-ca.der";
const CA_PRIVATE_KEY_FILE: &str = "orion-client-ca-key.der";
const CLIENT_CERTIFICATE_FILE: &str = "orion-client-cert.der";
const CLIENT_PRIVATE_KEY_FILE: &str = "orion-client-key.der";
const PQ_CA_PUBLIC_KEY_FILE: &str = "orion-client-pq-ca-public.bin";
const PQ_CA_PRIVATE_KEY_FILE: &str = "orion-client-pq-ca-private.bin";
const CLIENT_PQ_CERTIFICATE_FILE: &str = "orion-client-pq-cert.json";
const CLIENT_PQ_PRIVATE_KEY_FILE: &str = "orion-client-pq-private.bin";

#[derive(Subcommand)]
pub enum KeyNegoCmd {
    /// Creates the Orion client CA on the operator workstation.
    InitClientCa {
        #[arg(long)]
        name: String,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Issues an Orion client certificate from the operator client CA.
    IssueClient {
        #[arg(long)]
        name: String,
        #[arg(long)]
        ca_certificate: PathBuf,
        #[arg(long)]
        ca_private_key: PathBuf,
        #[arg(long)]
        ca_pq_private_key: PathBuf,
        #[arg(long)]
        wireguard_public_key: String,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Prints the canonical SHA-256 fingerprint of a DER certificate.
    Fingerprint {
        #[arg(long)]
        certificate: PathBuf,
    },
    /// Exercises mTLS and protocol validation without committing the WG slot.
    Probe {
        #[arg(long)]
        endpoint: String,
        #[arg(long)]
        server_name: String,
        #[arg(long)]
        gateway_certificate: PathBuf,
        #[arg(long)]
        client_certificate: PathBuf,
        #[arg(long)]
        client_private_key: PathBuf,
        #[arg(long)]
        gateway_pq_certificate: PathBuf,
        #[arg(long)]
        client_pq_certificate: PathBuf,
        #[arg(long)]
        client_pq_private_key: PathBuf,
        #[arg(long)]
        client_wg_private_key_file: PathBuf,
        #[arg(long)]
        gateway_wg_public_key: String,
        #[arg(long, value_enum)]
        mode: Mode,
        #[arg(long)]
        static_psk_file: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, ValueEnum)]
pub enum Mode {
    Classic,
    StaticPsk,
    MlKem,
}

impl From<Mode> for ProtectionMode {
    fn from(value: Mode) -> Self {
        match value {
            Mode::Classic => Self::Classic,
            Mode::StaticPsk => Self::StaticPsk,
            Mode::MlKem => Self::MlKem,
        }
    }
}

pub async fn run(command: KeyNegoCmd) -> Result<()> {
    match command {
        KeyNegoCmd::InitClientCa { name, output_dir } => init_client_ca(&name, &output_dir),
        KeyNegoCmd::IssueClient {
            name,
            ca_certificate,
            ca_private_key,
            ca_pq_private_key,
            wireguard_public_key,
            output_dir,
        } => issue_client(
            &name,
            &wireguard_public_key,
            &ca_certificate,
            &ca_private_key,
            &ca_pq_private_key,
            &output_dir,
        ),
        KeyNegoCmd::Fingerprint { certificate } => {
            let bytes = std::fs::read(&certificate)
                .with_context(|| format!("reading {}", certificate.display()))?;
            if let Ok(certificate) = serde_json::from_slice::<PqCertificate>(&bytes) {
                println!("{}", certificate.fingerprint()?);
            } else {
                println!(
                    "{}",
                    helios_key_negotiation::certificate_fingerprint_der(&bytes)
                );
            }
            Ok(())
        }
        KeyNegoCmd::Probe {
            endpoint,
            server_name,
            gateway_certificate,
            client_certificate,
            client_private_key,
            gateway_pq_certificate,
            client_pq_certificate,
            client_pq_private_key,
            client_wg_private_key_file,
            gateway_wg_public_key,
            mode,
            static_psk_file,
        } => {
            check_private_permissions(&client_private_key)?;
            check_private_permissions(&client_pq_private_key)?;
            check_private_permissions(&client_wg_private_key_file)?;
            let client_wg_private_key = Zeroizing::new(
                std::fs::read_to_string(&client_wg_private_key_file)
                    .with_context(|| format!("reading {}", client_wg_private_key_file.display()))?,
            );
            let client_wg_public_key =
                aether::wg::public_from_private(client_wg_private_key.trim())
                    .context("deriving the client WireGuard public key")?;
            let static_psk = match static_psk_file {
                Some(path) => {
                    check_private_permissions(&path)?;
                    Some(Zeroizing::new(
                        std::fs::read_to_string(&path)
                            .with_context(|| format!("reading {}", path.display()))?,
                    ))
                }
                None => None,
            };
            let negotiated = orion_core::key_negotiation::prepare(
                KeyNegotiationClient {
                    remote: endpoint,
                    server_name,
                    client_certificate_chain: vec![read(&client_certificate)?],
                    client_private_key: read(&client_private_key)?,
                    client_pq_certificate: read(&client_pq_certificate)?,
                    client_pq_private_key: read(&client_pq_private_key)?,
                    gateway_ca: read(&gateway_certificate)?,
                    gateway_pq_certificate: serde_json::from_slice(&read(&gateway_pq_certificate)?)
                        .context("parsing the gateway PQ certificate")?,
                    minimum_mode: mode.into(),
                },
                mode.into(),
                &client_wg_public_key,
                &gateway_wg_public_key,
                static_psk.as_ref().map(|value| value.trim()),
            )
            .await?;
            println!(
                "accepted mode {:?}; confirmation window {}s",
                negotiated.mode,
                negotiated.confirmation_timeout.as_secs()
            );
            drop(negotiated);
            println!("transaction intentionally left unconfirmed; gateway rollback requested");
            Ok(())
        }
    }
}

fn init_client_ca(name: &str, output_dir: &Path) -> Result<()> {
    reject_existing(
        output_dir,
        &[
            CA_CERTIFICATE_FILE,
            CA_PRIVATE_KEY_FILE,
            PQ_CA_PUBLIC_KEY_FILE,
            PQ_CA_PRIVATE_KEY_FILE,
        ],
    )?;
    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];
    params.distinguished_name = distinguished_name(name);
    set_validity(&mut params, 3650);
    let key = KeyPair::generate().context("generating the client CA key")?;
    let certificate = params.self_signed(&key).context("creating the client CA")?;
    write_public(
        &output_dir.join(CA_CERTIFICATE_FILE),
        certificate.der().as_ref(),
    )?;
    write_secret(&output_dir.join(CA_PRIVATE_KEY_FILE), &key.serialize_der())?;
    let (pq_private_key, pq_public_key) =
        generate_ml_dsa_65_keypair().context("generating the client PQ CA")?;
    write_public(&output_dir.join(PQ_CA_PUBLIC_KEY_FILE), &pq_public_key)?;
    write_secret(
        &output_dir.join(PQ_CA_PRIVATE_KEY_FILE),
        pq_private_key.as_slice(),
    )?;
    println!(
        "client CA: {}",
        output_dir.join(CA_CERTIFICATE_FILE).display()
    );
    println!(
        "private key: {}",
        output_dir.join(CA_PRIVATE_KEY_FILE).display()
    );
    println!(
        "PQ CA public key: {}",
        output_dir.join(PQ_CA_PUBLIC_KEY_FILE).display()
    );
    println!(
        "PQ CA private key: {}",
        output_dir.join(PQ_CA_PRIVATE_KEY_FILE).display()
    );
    Ok(())
}

fn issue_client(
    name: &str,
    wireguard_public_key: &str,
    ca_certificate_path: &Path,
    ca_private_key_path: &Path,
    ca_pq_private_key_path: &Path,
    output_dir: &Path,
) -> Result<()> {
    reject_existing(
        output_dir,
        &[
            CLIENT_CERTIFICATE_FILE,
            CLIENT_PRIVATE_KEY_FILE,
            CLIENT_PQ_CERTIFICATE_FILE,
            CLIENT_PQ_PRIVATE_KEY_FILE,
        ],
    )?;
    check_private_permissions(ca_private_key_path)?;
    check_private_permissions(ca_pq_private_key_path)?;
    aether::wg::validate_key(wireguard_public_key).context("invalid WireGuard public key")?;
    let ca_der = read(ca_certificate_path)?;
    let ca_params = CertificateParams::from_ca_cert_der(&CertificateDer::from(ca_der))
        .context("parsing the client CA certificate")?;
    anyhow::ensure!(
        matches!(ca_params.is_ca, IsCa::Ca(_)),
        "issuer certificate is not a CA"
    );
    let ca_key_der = Zeroizing::new(read(ca_private_key_path)?);
    let ca_key = KeyPair::try_from(ca_key_der.as_slice()).context("parsing the client CA key")?;
    let ca = ca_params
        .self_signed(&ca_key)
        .context("reconstructing the client CA issuer")?;

    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params.distinguished_name = distinguished_name(name);
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
    set_validity(&mut params, 825);
    let key = KeyPair::generate().context("generating the Orion client key")?;
    let certificate = params
        .signed_by(&key, &ca, &ca_key)
        .context("issuing the Orion client certificate")?;

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;
    write_public(
        &output_dir.join(CLIENT_CERTIFICATE_FILE),
        certificate.der().as_ref(),
    )?;
    write_secret(
        &output_dir.join(CLIENT_PRIVATE_KEY_FILE),
        &key.serialize_der(),
    )?;
    let ca_pq_private_key = Zeroizing::new(read(ca_pq_private_key_path)?);
    let (client_pq_private_key, client_pq_public_key) =
        generate_ml_dsa_65_keypair().context("generating the Orion PQ identity")?;
    let now = unix_time_now()?;
    let pq_certificate = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: random_serial()?,
            subject: name.trim().to_string(),
            issuer: "orion-client-pq-ca".to_string(),
            role: PqCertificateRole::Client,
            wireguard_public_key: wireguard_public_key.trim().to_string(),
            ml_dsa_65_public_key: base64::engine::general_purpose::STANDARD
                .encode(client_pq_public_key),
            not_before_unix: now.saturating_sub(300),
            not_after_unix: now + 825 * 24 * 60 * 60,
            ml_dsa_65_signature: String::new(),
        },
        ca_pq_private_key.as_slice(),
    )
    .context("issuing the Orion PQ certificate")?;
    write_public(
        &output_dir.join(CLIENT_PQ_CERTIFICATE_FILE),
        &serde_json::to_vec_pretty(&pq_certificate).context("encoding the Orion PQ certificate")?,
    )?;
    write_secret(
        &output_dir.join(CLIENT_PQ_PRIVATE_KEY_FILE),
        client_pq_private_key.as_slice(),
    )?;
    println!(
        "certificate: {}",
        output_dir.join(CLIENT_CERTIFICATE_FILE).display()
    );
    println!(
        "sha256: {}",
        helios_key_negotiation::certificate_fingerprint_der(certificate.der().as_ref())
    );
    println!("PQ certificate sha256: {}", pq_certificate.fingerprint()?);
    Ok(())
}

fn distinguished_name(name: &str) -> DistinguishedName {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, name.trim());
    distinguished_name
}

fn set_validity(params: &mut CertificateParams, days: i64) {
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
}

fn random_serial() -> Result<[u8; 16]> {
    use aws_lc_rs::rand::{SecureRandom as _, SystemRandom};

    let mut serial = [0u8; 16];
    SystemRandom::new()
        .fill(&mut serial)
        .map_err(|_| anyhow::anyhow!("system CSPRNG unavailable"))?;
    Ok(serial)
}

fn unix_time_now() -> Result<u64> {
    Ok(std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_secs())
}

fn reject_existing(directory: &Path, files: &[&str]) -> Result<()> {
    for file in files {
        let path = directory.join(file);
        anyhow::ensure!(
            !path.exists(),
            "{} already exists; refusing to overwrite private identity material",
            path.display()
        );
    }
    Ok(())
}

fn read(path: &Path) -> Result<Vec<u8>> {
    std::fs::read(path).with_context(|| format!("reading {}", path.display()))
}

fn write_public(path: &Path, contents: &[u8]) -> Result<()> {
    std::fs::write(path, contents).with_context(|| format!("writing {}", path.display()))
}

fn write_secret(path: &Path, contents: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    file.write_all(contents)
        .with_context(|| format!("writing {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("syncing {}", path.display()))
}

#[cfg(unix)]
fn check_private_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;
    let mode = std::fs::metadata(path)?.permissions().mode() & 0o777;
    anyhow::ensure!(
        mode & 0o077 == 0,
        "{} permissions are {mode:o}; expected 0600 or stricter",
        path.display()
    );
    Ok(())
}

#[cfg(not(unix))]
fn check_private_permissions(_path: &Path) -> Result<()> {
    Ok(())
}
