//! Operator tooling for key-negotiation certificates and protocol probes.

use std::{
    fs::OpenOptions,
    io::Write as _,
    path::{Path, PathBuf},
};

use aether::key_negotiation::{
    generate_ml_dsa_87_keypair, issue_pq_certificate, PqCertificate, PqCertificateRole,
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

/// Variable d'environnement qui déplace la CA opérateur.
///
/// Pour l'opérateur qui en gère plusieurs — une par flotte. Le reste du temps
/// elle n'a pas à être posée : c'est l'emplacement fixe qui répond.
pub const CLIENT_CA_DIR_ENV: &str = "HELIOS_CLIENT_CA_DIR";

/// Emplacement **fixe** de la CA cliente sur le poste opérateur.
///
/// # Pourquoi il ne peut pas être relatif
///
/// Le défaut était `./orion-client-ca`, donc relatif au dossier courant. La
/// même commande lancée d'un autre répertoire cherchait ailleurs, ne trouvait
/// rien, et le message conseillait alors d'en créer une neuve — ce qui
/// **orpheline la flotte entière** : `heliosd init-key-negotiation` épingle la
/// CA cliente, et la gateway refuse tout certificat émis par une autre. Un
/// défaut qui dépend du répertoire courant transforme un `cd` en incident.
///
/// L'emplacement suit donc le compte, comme le coffre Orion et comme le fait
/// déjà la gateway avec `/var/lib/helios`. `HELIOS_CLIENT_CA_DIR` le déplace,
/// `--client-ca-dir` le remplace pour une commande.
///
/// # Ce qu'il contient
///
/// Deux clés privées de CA — TLS et ML-DSA-87 — c'est-à-dire le pouvoir
/// d'émettre des certificats que la gateway croira. Le répertoire naît en 0700
/// et les fichiers en 0600.
pub fn default_client_ca_dir() -> PathBuf {
    // `var_os` rend `Some("")` pour une variable posée mais vide — ce qu'un
    // `export HELIOS_CLIENT_CA_DIR=` ou un script produit sans le vouloir. La
    // prendre pour un chemin donnait un message d'erreur qui ne nommait aucun
    // répertoire, donc inexploitable. Vide vaut absente.
    if let Some(directory) = std::env::var_os(CLIENT_CA_DIR_ENV).filter(|value| !value.is_empty()) {
        return PathBuf::from(directory);
    }
    // The tool's former name, kept on purpose: this directory holds the
    // operator client CA the gateway already pins. Renaming it would make the
    // tool mint a new CA and break every admitted client.
    directories::ProjectDirs::from("net", "helios", "helios-ctl")
        .map(|dirs| dirs.data_dir().join("orion-client-ca"))
        // Dernier recours seulement : sans répertoire de données, mieux vaut un
        // chemin utilisable qu'un échec, mais il reste relatif — d'où le
        // message de `check_client_ca`, qui dit toujours où il a cherché.
        .unwrap_or_else(|| PathBuf::from("orion-client-ca"))
}

const CA_CERTIFICATE_FILE: &str = "orion-client-ca.der";
const CA_PRIVATE_KEY_FILE: &str = "orion-client-ca-key.der";
const CLIENT_CERTIFICATE_FILE: &str = "orion-client-cert.der";
const CLIENT_PRIVATE_KEY_FILE: &str = "orion-client-key.der";
const PQ_CA_PUBLIC_KEY_FILE: &str = "orion-client-pq-ca-public.bin";
const PQ_CA_PRIVATE_KEY_FILE: &str = "orion-client-pq-ca-private.bin";
const CLIENT_PQ_CERTIFICATE_FILE: &str = "orion-client-pq-cert.json";
const CLIENT_PQ_PRIVATE_KEY_FILE: &str = "orion-client-pq-private.bin";
/// The production validity used by the ordinary provisioning path.
pub const DEFAULT_CLIENT_VALIDITY_SECS: u64 = 825 * 24 * 60 * 60;
/// Floor on a client leaf's life, for lifecycle tests only.
///
/// A renewal opens at 80 % of the life, and the leaf is backdated by
/// [`CLOCK_SKEW_BACKDATE_SECS`], so the wait an operator actually sits through
/// is `0.8 * (validity + backdate) - backdate` and the window left to act on
/// the result is `0.2 * (validity + backdate)`. Two minutes of validity leaves
/// under two minutes to act.
///
/// That is deliberately close to the edge: below it, a leaf can expire while
/// the profile is still being admitted, and the test then measures operator
/// typing speed instead of the renewal window it was meant to exercise. The
/// floor is what keeps that failure mode a choice rather than an accident.
pub const MIN_CLIENT_VALIDITY_SECS: u64 = 2 * 60;

/// How far a freshly issued leaf is backdated.
///
/// Not a correction for a badly synchronised clock — it covers the moment when
/// there is no synchronisation yet: a gateway restarted before its first NTP
/// exchange, a workstation whose clock drifted while it was off. A verifier
/// whose clock sits slightly behind the issuer's would otherwise refuse a leaf
/// that is genuinely valid.
pub const CLOCK_SKEW_BACKDATE_SECS: u64 = 300;

#[derive(Subcommand)]
pub enum KeyNegoCmd {
    /// Creates the Orion client CA on the operator workstation.
    InitClientCa {
        #[arg(long)]
        name: String,
        /// Où écrire la CA. Défaut : l'emplacement fixe du compte
        /// (`HELIOS_CLIENT_CA_DIR` le déplace).
        #[arg(long)]
        output_dir: Option<PathBuf>,
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
        /// Validité des feuilles clientes, en secondes. Réservé aux profils
        /// de test ; défaut : 825 jours. Minimum : 600 secondes.
        #[arg(long)]
        validity_secs: Option<u64>,
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
        /// `CA-PQ` anchor of the gateway's trust domain, base64 ML-DSA-87.
        ///
        /// Required against a gateway that carries a domain, since it then
        /// serves a leaf `CA-PQ` issued rather than a self-signed one
        /// (ADR-008 §13.1). Omitted for a gateway that carries none, where the
        /// pinned leaf is the whole of the trust.
        #[arg(long)]
        gateway_ca_pq_public_key: Option<PathBuf>,
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
        KeyNegoCmd::InitClientCa { name, output_dir } => {
            let output_dir = output_dir.unwrap_or_else(default_client_ca_dir);
            init_client_ca(&name, &output_dir)
        }
        KeyNegoCmd::IssueClient {
            name,
            ca_certificate,
            ca_private_key,
            ca_pq_private_key,
            wireguard_public_key,
            output_dir,
            validity_secs,
        } => issue_client_with_validity(
            &name,
            &wireguard_public_key,
            &ca_certificate,
            &ca_private_key,
            &ca_pq_private_key,
            &output_dir,
            validity_secs.unwrap_or(DEFAULT_CLIENT_VALIDITY_SECS),
        ),
        KeyNegoCmd::Fingerprint { certificate } => {
            let bytes = std::fs::read(&certificate)
                .with_context(|| format!("reading {}", certificate.display()))?;
            if let Ok(certificate) = serde_json::from_slice::<PqCertificate>(&bytes) {
                println!("{}", certificate.fingerprint()?);
            } else {
                println!(
                    "{}",
                    aether_key_negotiation::certificate_fingerprint_der(&bytes)
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
            gateway_ca_pq_public_key,
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
            let ca_pq_anchor = match gateway_ca_pq_public_key {
                Some(path) => Some(
                    aether::certificates::encoding::MlDsa87PublicKey::parse(
                        std::fs::read_to_string(&path)
                            .with_context(|| format!("reading {}", path.display()))?
                            .trim(),
                    )
                    .context("the CA-PQ anchor is not a readable ML-DSA-87 public key")?
                    .as_bytes()
                    .to_vec(),
                ),
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
                    gateway_ca_pq_public_key: ca_pq_anchor,
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
    // 0700 : ce répertoire porte deux clés privées de CA, c'est-à-dire le
    // pouvoir d'émettre des certificats que la gateway croira.
    aether::private_file::create_private_dir(output_dir)
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
        generate_ml_dsa_87_keypair().context("generating the client PQ CA")?;
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

/// The four artifacts of a client identity, still in memory.
///
/// Kept as one value because they are only ever useful together: a
/// certificate without its private key authenticates nothing, and a key
/// without its certificate cannot be presented. Callers either write them to
/// four files (`issue-client`) or seal them into one bundle (`enroll`).
pub struct ClientMaterial {
    pub certificate_der: Vec<u8>,
    pub private_key_der: Zeroizing<Vec<u8>>,
    pub pq_certificate_json: Vec<u8>,
    pub pq_private_key: Zeroizing<Vec<u8>>,
    /// SHA-256 of the DER certificate — declared at admission.
    pub certificate_sha256: String,
    /// SHA-256 of the PQ certificate — declared at admission, and the value
    /// that actually anchors authentication.
    pub pq_certificate_sha256: String,
}

/// Issues a client identity from the operator CA, without touching the disk.
///
/// Both `issue-client` and `enroll` go through here: two issuance paths would
/// eventually disagree on validity, on the WireGuard binding, or on the role
/// byte — and the divergence would only show up as a refused negotiation.
pub fn issue_client_material(
    name: &str,
    wireguard_public_key: &str,
    ca_certificate_path: &Path,
    ca_private_key_path: &Path,
    ca_pq_private_key_path: &Path,
) -> Result<ClientMaterial> {
    issue_client_material_with_validity(
        name,
        wireguard_public_key,
        ca_certificate_path,
        ca_private_key_path,
        ca_pq_private_key_path,
        DEFAULT_CLIENT_VALIDITY_SECS,
    )
}

/// Issues a client identity with an explicit validity, for lifecycle tests.
///
/// The TLS and PQ leaves receive the same interval. Keeping this test hook in
/// the single issuance helper is important: generating a short PQ leaf while
/// leaving TLS at 825 days would exercise a split-brain certificate state, not
/// the renewal planner.
pub fn issue_client_material_with_validity(
    name: &str,
    wireguard_public_key: &str,
    ca_certificate_path: &Path,
    ca_private_key_path: &Path,
    ca_pq_private_key_path: &Path,
    validity_secs: u64,
) -> Result<ClientMaterial> {
    anyhow::ensure!(
        validity_secs >= MIN_CLIENT_VALIDITY_SECS,
        "client validity must be at least {MIN_CLIENT_VALIDITY_SECS} seconds"
    );
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
    set_validity_secs(&mut params, validity_secs);
    let key = KeyPair::generate().context("generating the Orion client key")?;
    let certificate = params
        .signed_by(&key, &ca, &ca_key)
        .context("issuing the Orion client certificate")?;

    let ca_pq_private_key = Zeroizing::new(read(ca_pq_private_key_path)?);
    let (client_pq_private_key, client_pq_public_key) =
        generate_ml_dsa_87_keypair().context("generating the Orion PQ identity")?;
    let now = unix_time_now()?;
    let pq_certificate = issue_pq_certificate(
        PqCertificate {
            version: PQ_CERTIFICATE_VERSION,
            serial: random_serial()?,
            subject: name.trim().to_string(),
            issuer: "orion-client-pq-ca".to_string(),
            role: PqCertificateRole::Client,
            wireguard_public_key: wireguard_public_key.trim().to_string(),
            ml_dsa_87_public_key: base64::engine::general_purpose::STANDARD
                .encode(client_pq_public_key),
            not_before_unix: now.saturating_sub(CLOCK_SKEW_BACKDATE_SECS),
            not_after_unix: now
                .checked_add(validity_secs)
                .context("client validity exceeds the Unix timestamp range")?,
            ml_dsa_87_signature: String::new(),
        },
        ca_pq_private_key.as_slice(),
    )
    .context("issuing the Orion PQ certificate")?;

    Ok(ClientMaterial {
        certificate_sha256: aether_key_negotiation::certificate_fingerprint_der(
            certificate.der().as_ref(),
        ),
        pq_certificate_sha256: pq_certificate.fingerprint()?,
        certificate_der: certificate.der().to_vec(),
        private_key_der: Zeroizing::new(key.serialize_der()),
        pq_certificate_json: serde_json::to_vec_pretty(&pq_certificate)
            .context("encoding the Orion PQ certificate")?,
        pq_private_key: client_pq_private_key,
    })
}

/// Reloads an identity already written by `issue-client`.
///
/// Needed whenever admission and profile assembly are two separate steps: the
/// gateway was admitted against *these* fingerprints, so reissuing fresh
/// certificates in between would hand the client an identity the gateway does
/// not know — and the refusal would come much later, with nothing pointing
/// back to the reissue.
pub fn load_client_material(directory: &Path) -> Result<ClientMaterial> {
    let certificate_der = read(&directory.join(CLIENT_CERTIFICATE_FILE))?;
    let pq_certificate_json = read(&directory.join(CLIENT_PQ_CERTIFICATE_FILE))?;
    let pq_certificate: PqCertificate = serde_json::from_slice(&pq_certificate_json)
        .context("the client PQ certificate is not a readable JSON document")?;
    Ok(ClientMaterial {
        certificate_sha256: aether_key_negotiation::certificate_fingerprint_der(&certificate_der),
        pq_certificate_sha256: pq_certificate.fingerprint()?,
        certificate_der,
        private_key_der: Zeroizing::new(read(&directory.join(CLIENT_PRIVATE_KEY_FILE))?),
        pq_certificate_json,
        pq_private_key: Zeroizing::new(read(&directory.join(CLIENT_PQ_PRIVATE_KEY_FILE))?),
    })
}

/// The default-validity wrapper. Only the tests below reach it: the command
/// line always passes a validity, so gating it keeps the binary from carrying
/// a function nothing calls.
#[cfg(test)]
fn issue_client(
    name: &str,
    wireguard_public_key: &str,
    ca_certificate_path: &Path,
    ca_private_key_path: &Path,
    ca_pq_private_key_path: &Path,
    output_dir: &Path,
) -> Result<()> {
    issue_client_with_validity(
        name,
        wireguard_public_key,
        ca_certificate_path,
        ca_private_key_path,
        ca_pq_private_key_path,
        output_dir,
        DEFAULT_CLIENT_VALIDITY_SECS,
    )
}

fn issue_client_with_validity(
    name: &str,
    wireguard_public_key: &str,
    ca_certificate_path: &Path,
    ca_private_key_path: &Path,
    ca_pq_private_key_path: &Path,
    output_dir: &Path,
    validity_secs: u64,
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
    let material = issue_client_material_with_validity(
        name,
        wireguard_public_key,
        ca_certificate_path,
        ca_private_key_path,
        ca_pq_private_key_path,
        validity_secs,
    )?;

    std::fs::create_dir_all(output_dir)
        .with_context(|| format!("creating {}", output_dir.display()))?;
    write_public(
        &output_dir.join(CLIENT_CERTIFICATE_FILE),
        &material.certificate_der,
    )?;
    write_secret(
        &output_dir.join(CLIENT_PRIVATE_KEY_FILE),
        &material.private_key_der,
    )?;
    write_public(
        &output_dir.join(CLIENT_PQ_CERTIFICATE_FILE),
        &material.pq_certificate_json,
    )?;
    write_secret(
        &output_dir.join(CLIENT_PQ_PRIVATE_KEY_FILE),
        &material.pq_private_key,
    )?;
    println!(
        "certificate: {}",
        output_dir.join(CLIENT_CERTIFICATE_FILE).display()
    );
    println!("sha256: {}", material.certificate_sha256);
    println!("PQ certificate sha256: {}", material.pq_certificate_sha256);
    Ok(())
}

fn distinguished_name(name: &str) -> DistinguishedName {
    let mut distinguished_name = DistinguishedName::new();
    distinguished_name.push(DnType::CommonName, name.trim());
    distinguished_name
}

fn set_validity(params: &mut CertificateParams, days: i64) {
    set_validity_secs(params, (days as u64).saturating_mul(24 * 60 * 60));
}

fn set_validity_secs(params: &mut CertificateParams, validity_secs: u64) {
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc()
        + time::Duration::seconds(i64::try_from(validity_secs).unwrap_or(i64::MAX));
}

fn random_serial() -> Result<[u8; 16]> {
    let mut serial = [0u8; 16];
    aether::random::fill_public(&mut serial)
        .map_err(|error| anyhow::anyhow!("the approved DRBG refused: {error}"))?;
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes the tests that write `HELIOS_CLIENT_CA_DIR`.
    ///
    /// The variable is process-wide and `cargo test` runs threads in
    /// parallel, so "this test owns it" is only true if something enforces
    /// it. Nothing did: one test set the variable while the other removed
    /// it, and which won depended on timing. It stayed hidden until the
    /// ML-DSA-87 migration made neighbouring tests slower and widened the
    /// window — a latent race does not become real, it becomes visible.
    static CLIENT_CA_ENV: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// The CA location must not depend on where the command was launched.
    ///
    /// The old default was `./orion-client-ca`. A `cd` therefore silently
    /// pointed the tool at nothing, and the error then advised creating a new
    /// CA — which orphans the whole fleet, since `heliosd init-key-negotiation`
    /// pins the client CA and the gateway refuses certificates from any other.
    /// A default that turns a `cd` into an incident is not a default.
    #[test]
    fn the_client_ca_location_is_absolute_and_stable() {
        // The environment override is process-wide; the lock is what makes
        // owning it true.
        let _owned = CLIENT_CA_ENV
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        std::env::remove_var(CLIENT_CA_DIR_ENV);

        let from_root = {
            let _guard = std::env::set_current_dir("/").is_ok();
            default_client_ca_dir()
        };
        let from_temp = {
            let _guard = std::env::set_current_dir(std::env::temp_dir()).is_ok();
            default_client_ca_dir()
        };

        assert_eq!(
            from_root, from_temp,
            "l'emplacement de la CA ne doit pas suivre le répertoire courant"
        );
        assert!(
            from_root.is_absolute(),
            "obtenu un chemin relatif : {}",
            from_root.display()
        );
    }

    /// The override exists for the operator who keeps several fleets apart.
    ///
    /// An **empty** value counts as absent: `export HELIOS_CLIENT_CA_DIR=` is
    /// what a script writes by accident, and taking it for a path produced an
    /// error message naming no directory at all — unusable.
    #[test]
    fn the_environment_variable_moves_the_client_ca_unless_it_is_empty() {
        let _owned = CLIENT_CA_ENV
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let elsewhere = std::env::temp_dir().join("helios-ca-ailleurs");
        std::env::set_var(CLIENT_CA_DIR_ENV, &elsewhere);
        assert_eq!(default_client_ca_dir(), elsewhere);

        std::env::set_var(CLIENT_CA_DIR_ENV, "");
        let fallback = default_client_ca_dir();
        assert!(
            !fallback.as_os_str().is_empty(),
            "une variable vide ne doit pas produire un chemin vide"
        );
        std::env::remove_var(CLIENT_CA_DIR_ENV);
    }

    fn test_directory(name: &str) -> PathBuf {
        let directory = std::env::temp_dir().join(format!(
            "helios-key-nego-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        directory
    }

    #[test]
    fn cli_modes_map_one_to_one_to_protocol_modes() {
        assert_eq!(ProtectionMode::from(Mode::Classic), ProtectionMode::Classic);
        assert_eq!(
            ProtectionMode::from(Mode::StaticPsk),
            ProtectionMode::StaticPsk
        );
        assert_eq!(ProtectionMode::from(Mode::MlKem), ProtectionMode::MlKem);
    }

    #[test]
    fn existing_identity_material_is_never_overwritten() {
        let directory = test_directory("reject-existing");
        std::fs::create_dir_all(&directory).unwrap();
        std::fs::write(directory.join("private.key"), b"keep").unwrap();

        let error = reject_existing(&directory, &["absent", "private.key"])
            .expect_err("existing material must be refused");
        assert!(error.to_string().contains("private.key"));
        assert_eq!(
            std::fs::read(directory.join("private.key")).unwrap(),
            b"keep"
        );
        assert!(reject_existing(&directory, &["absent"]).is_ok());

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn secret_writer_and_permission_check_enforce_private_files() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = test_directory("permissions");
        std::fs::create_dir_all(&directory).unwrap();
        let secret = directory.join("secret");
        write_secret(&secret, b"sensitive").unwrap();
        assert_eq!(
            std::fs::metadata(&secret).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(check_private_permissions(&secret).is_ok());
        assert!(write_secret(&secret, b"replacement").is_err());
        assert_eq!(std::fs::read(&secret).unwrap(), b"sensitive");

        let exposed = directory.join("exposed");
        std::fs::write(&exposed, b"secret").unwrap();
        std::fs::set_permissions(&exposed, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = check_private_permissions(&exposed).expect_err("world-readable secret");
        assert!(error.to_string().contains("permissions are 644"));

        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn client_ca_and_bound_client_identity_round_trip_through_files() {
        let root = test_directory("issuance");
        let ca = root.join("ca");
        let client = root.join("client");
        init_client_ca("  Orion test CA  ", &ca).expect("create client CA");

        let keypair = aether::wg::generate_keypair().unwrap();
        issue_client(
            "  portable  ",
            &keypair.public_key,
            &ca.join(CA_CERTIFICATE_FILE),
            &ca.join(CA_PRIVATE_KEY_FILE),
            &ca.join(PQ_CA_PRIVATE_KEY_FILE),
            &client,
        )
        .expect("issue client identity");

        let loaded = load_client_material(&client).expect("reload issued identity");
        assert!(!loaded.certificate_der.is_empty());
        assert!(!loaded.private_key_der.is_empty());
        assert!(!loaded.pq_private_key.is_empty());
        assert_eq!(
            loaded.certificate_sha256,
            aether_key_negotiation::certificate_fingerprint_der(&loaded.certificate_der)
        );
        let pq_certificate: PqCertificate =
            serde_json::from_slice(&loaded.pq_certificate_json).unwrap();
        assert_eq!(pq_certificate.subject, "portable");
        assert_eq!(pq_certificate.role, PqCertificateRole::Client);
        assert_eq!(pq_certificate.wireguard_public_key, keypair.public_key);
        assert_eq!(
            loaded.pq_certificate_sha256,
            pq_certificate.fingerprint().unwrap()
        );

        assert!(
            issue_client(
                "portable",
                &keypair.public_key,
                &ca.join(CA_CERTIFICATE_FILE),
                &ca.join(CA_PRIVATE_KEY_FILE),
                &ca.join(PQ_CA_PRIVATE_KEY_FILE),
                &client,
            )
            .is_err(),
            "issuing again must not replace the admitted identity"
        );

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn short_validity_applies_to_the_pq_leaf_and_rejects_risky_values() {
        let root = test_directory("short-validity");
        let ca = root.join("ca");
        init_client_ca("Orion test CA", &ca).unwrap();
        let keypair = aether::wg::generate_keypair().unwrap();

        let material = issue_client_material_with_validity(
            "renewal-test",
            &keypair.public_key,
            &ca.join(CA_CERTIFICATE_FILE),
            &ca.join(CA_PRIVATE_KEY_FILE),
            &ca.join(PQ_CA_PRIVATE_KEY_FILE),
            600,
        )
        .expect("short-lived identity");
        let certificate: PqCertificate =
            serde_json::from_slice(&material.pq_certificate_json).unwrap();
        let now = unix_time_now().unwrap();
        assert!(certificate.not_after_unix >= now + 590);
        assert!(certificate.not_after_unix <= now + 600);
        let tls = aether::certificates::encoding::DerCertificate::new(material.certificate_der)
            .expect("short-lived TLS leaf");
        let tls_facts = aether::certificates::x509::inspect(&tls).expect("inspect TLS leaf");
        assert!(tls_facts.not_after >= now + 590);
        assert!(tls_facts.not_after <= now + 600);

        let error = match issue_client_material_with_validity(
            "renewal-test",
            &keypair.public_key,
            &ca.join(CA_CERTIFICATE_FILE),
            &ca.join(CA_PRIVATE_KEY_FILE),
            &ca.join(PQ_CA_PRIVATE_KEY_FILE),
            MIN_CLIENT_VALIDITY_SECS - 1,
        ) {
            Ok(_) => panic!("a profile must leave time to complete admission"),
            Err(error) => error,
        };
        assert!(error
            .to_string()
            .contains(&format!("at least {MIN_CLIENT_VALIDITY_SECS} seconds")));

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn invalid_wireguard_identity_is_refused_before_client_files_exist() {
        let root = test_directory("invalid-wg");
        let ca = root.join("ca");
        let client = root.join("client");
        init_client_ca("Orion test CA", &ca).unwrap();

        let error = issue_client(
            "portable",
            "not-a-wireguard-key",
            &ca.join(CA_CERTIFICATE_FILE),
            &ca.join(CA_PRIVATE_KEY_FILE),
            &ca.join(PQ_CA_PRIVATE_KEY_FILE),
            &client,
        )
        .expect_err("invalid peer identity");
        assert!(error.to_string().contains("invalid WireGuard public key"));
        assert!(!client.exists());

        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn helpers_report_missing_files_and_generate_fresh_serials() {
        let directory = test_directory("helpers");
        let missing = directory.join("missing");
        let error = read(&missing).expect_err("missing file");
        assert!(error.to_string().contains(&missing.display().to_string()));

        let first = random_serial().unwrap();
        let second = random_serial().unwrap();
        assert_ne!(first, second);
        assert!(unix_time_now().unwrap() > 1_700_000_000);
    }
}
