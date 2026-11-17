//! The candidate identity of a gateway rotation: sealing, promotion and
//! discard.

use super::*;
use aether::certificates::encoding::DerCertificate;

/// Public half of the candidate identity a renewal has sealed.
///
/// The private halves stay in the vault this module owns; what comes back is
/// only what the request and the transition have to carry.
pub(crate) struct SealedCandidate {
    pub(crate) pq_public_key: aether::certificates::encoding::MlDsa87PublicKey,
    /// Present exactly when the renewal replaces the TLS leaf too.
    pub(crate) tls_certificate: Option<aether::certificates::encoding::DerCertificate>,
}

/// Which proof of continuity a gateway certificate request carries (spec §5).
pub(crate) enum RequestContinuity {
    /// Ordinary renewal: the leaf in service signs alongside the new key.
    FromActiveLeaf,
    /// The active private key is gone. §5 allows the operator to accept a
    /// request without it after an explicit local procedure, and the field is
    /// then **absent** — a signature nobody could check would read, in an
    /// audit, as one that proved continuity.
    KeyRecovery,
}

/// Sealing context of the candidate slot.
///
/// Bound to the epoch as well as to the peer, so a candidate prepared for one
/// decision cannot be unsealed as the candidate of another. This is the
/// freshness binding ADR-006 §2 asks for and that the active slot still
/// cannot express: the active identity carries no epoch of its own, the
/// candidate is created by a decision that has one.
pub(super) fn candidate_identity_context(
    gateway_wg_public_key: &str,
    gateway_identity_epoch: u64,
) -> helios_tpm::Context {
    helios_tpm::Context::new()
        .field("gateway_wg_public_key", gateway_wg_public_key.as_bytes())
        .field(
            "gateway_identity_epoch",
            &gateway_identity_epoch.to_be_bytes(),
        )
}

#[derive(serde::Serialize, serde::Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredCandidateIdentity {
    pub(super) pq_private_key: String,
    /// Present exactly when the renewal replaces the TLS leaf. `None` is not
    /// "empty": a renewal that keeps its TLS leaf must carry no candidate TLS
    /// key at all, or promotion would have two keys and no rule saying which
    /// one the next handshake is served under.
    pub(super) tls_private_key: Option<String>,
}

/// Generates and seals the next gateway private material (spec §11.1 step 1).
///
/// The keys are created **here** and never leave: what the ceremony receives
/// is a public key and a self-signed leaf. No path in the lifecycle moves a
/// gateway private key off the machine that created it.
pub(crate) fn seal_candidate_identity(
    secret: &SecretKey,
    gateway_wg_public_key: &str,
    server_name: &str,
    gateway_identity_epoch: u64,
    rotate_tls: bool,
) -> Result<SealedCandidate> {
    seal_candidate_identity_at(
        secret,
        gateway_wg_public_key,
        server_name,
        gateway_identity_epoch,
        rotate_tls,
        &next_private_keystore_path(),
        &next_certificate_path(),
    )
}

fn seal_candidate_identity_at(
    secret: &SecretKey,
    gateway_wg_public_key: &str,
    server_name: &str,
    gateway_identity_epoch: u64,
    rotate_tls: bool,
    keystore_path: &Path,
    certificate_path: &Path,
) -> Result<SealedCandidate> {
    use aether::certificates::encoding::MlDsa87PublicKey;

    let (pq_private_key, pq_public_key) =
        generate_ml_dsa_87_keypair().context("generating the candidate gateway PQ identity")?;

    let tls = if rotate_tls {
        Some(generate_candidate_tls(server_name)?)
    } else {
        None
    };

    let stored = Zeroizing::new(
        serde_json::to_vec(&StoredCandidateIdentity {
            pq_private_key: base64::engine::general_purpose::STANDARD
                .encode(pq_private_key.as_slice()),
            tls_private_key: tls
                .as_ref()
                .map(|(key, _)| base64::engine::general_purpose::STANDARD.encode(key.as_slice())),
        })
        .context("encoding the candidate gateway identity")?,
    );
    SealedKeystore::new(keystore_path, helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY)
        .store(
            secret,
            &candidate_identity_context(gateway_wg_public_key, gateway_identity_epoch),
            stored.as_slice(),
        )
        .context("sealing the candidate gateway keys")?;

    // The public leaf is written only once its private half is sealed. The
    // reverse order would leave a certificate on disk whose key the gateway
    // cannot prove it holds — and an operator reading the directory would see
    // a candidate that does not exist.
    let tls_certificate = match tls {
        Some((_, der)) => {
            write_public_atomic(certificate_path, der.as_bytes())
                .context("installing the candidate gateway TLS certificate")?;
            Some(der)
        }
        None => {
            // A previous attempt may have rotated TLS where this one does not.
            remove_if_present(certificate_path)?;
            None
        }
    };

    Ok(SealedCandidate {
        pq_public_key: MlDsa87PublicKey::new(pq_public_key.to_vec())
            .context("encoding the candidate gateway PQ public key")?,
        tls_certificate,
    })
}

fn generate_candidate_tls(server_name: &str) -> Result<(Zeroizing<Vec<u8>>, DerCertificate)> {
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    // Self-issued, self-signed and pinned, exactly like the active leaf:
    // §15 keeps this asymmetry deliberate, and `GatewayIdentityTransition`
    // refuses a leaf that chains to the client CA-TLS instead.
    let mut params = CertificateParams::new(vec![server_name.trim().to_string()])
        .context("server name is not valid for an X.509 certificate")?;
    params.is_ca = IsCa::NoCa;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::minutes(5);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(825);
    let key_pair = KeyPair::generate().context("generating the candidate gateway TLS key")?;
    let certificate = params
        .self_signed(&key_pair)
        .context("creating the candidate gateway TLS certificate")?;
    let der = DerCertificate::new(certificate.der().as_ref().to_vec())
        .context("encoding the candidate gateway TLS certificate")?;
    Ok((Zeroizing::new(key_pair.serialize_der()), der))
}

/// Signs a gateway certificate request under the keys this module holds
/// (spec §5).
///
/// Both unsealings happen inside this call and neither key leaves it. The
/// caller builds the request from the registry and never sees a private half.
pub(crate) fn sign_certificate_request(
    request: aether::certificates::gateway::GatewayCertificateRequest,
    secret: Option<&SecretKey>,
    dry_run: bool,
    gateway_wg_public_key: &str,
    gateway_identity_epoch: u64,
    continuity: RequestContinuity,
) -> Result<aether::certificates::gateway::GatewayCertificateRequest> {
    sign_certificate_request_at(
        request,
        secret,
        dry_run,
        gateway_wg_public_key,
        gateway_identity_epoch,
        continuity,
        &next_private_keystore_path(),
    )
}

fn sign_certificate_request_at(
    request: aether::certificates::gateway::GatewayCertificateRequest,
    secret: Option<&SecretKey>,
    dry_run: bool,
    gateway_wg_public_key: &str,
    gateway_identity_epoch: u64,
    continuity: RequestContinuity,
    keystore_path: &Path,
) -> Result<aether::certificates::gateway::GatewayCertificateRequest> {
    let unsealing =
        secret.context("TPM secret unavailable: the candidate gateway identity stays sealed")?;
    let sealed = SealedKeystore::new(keystore_path, helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY)
        .load(
            unsealing,
            &candidate_identity_context(gateway_wg_public_key, gateway_identity_epoch),
        )
        .context("unsealing the candidate gateway identity")?;
    let stored: StoredCandidateIdentity =
        serde_json::from_slice(&sealed).context("decoding the candidate gateway identity")?;
    let candidate_pq = Zeroizing::new(
        base64::engine::general_purpose::STANDARD
            .decode(&stored.pq_private_key)
            .context("decoding the candidate gateway PQ private key")?,
    );

    let signed = match continuity {
        RequestContinuity::FromActiveLeaf => {
            let active = load_active_private_identity(secret, dry_run, gateway_wg_public_key)
                .context("opening the gateway identity in service")?;
            let active_pq = Zeroizing::new(
                base64::engine::general_purpose::STANDARD
                    .decode(&active.pq_private_key)
                    .context("decoding the active gateway PQ private key")?,
            );
            request
                .sign(candidate_pq.as_slice(), Some(active_pq.as_slice()))
                .context("signing the gateway certificate request")?
        }
        RequestContinuity::KeyRecovery => request
            .sign(candidate_pq.as_slice(), None)
            .context("signing the gateway certificate request")?,
    };
    Ok(signed)
}

/// The candidate's self-signed TLS leaf, when this renewal replaces it.
///
/// Public by construction, and read without opening the vault: the file is
/// either there — the renewal rotates TLS — or it is not.
pub(crate) fn candidate_tls_certificate(
) -> Result<Option<aether::certificates::encoding::DerCertificate>> {
    read_candidate_tls_certificate(&next_certificate_path())
}

/// Reads a candidate TLS leaf from `path`; absent when the file is.
pub(crate) fn read_candidate_tls_certificate(
    path: &std::path::Path,
) -> Result<Option<aether::certificates::encoding::DerCertificate>> {
    match std::fs::read(path) {
        Ok(der) => Ok(Some(
            DerCertificate::new(der).with_context(|| format!("reading {}", path.display()))?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

/// Opens both sealed slots and proves they can form the transition's result.
///
/// Called before the registry promotion is persisted. A missing or malformed
/// candidate therefore leaves the old generation authoritative instead of
/// committing state that this machine cannot turn into a usable identity.
pub(crate) fn assert_candidate_identity_promotable(
    secret: &SecretKey,
    gateway_wg_public_key: &str,
    transition: &aether::certificates::gateway::GatewayIdentityTransition,
) -> Result<()> {
    let active = load_active_private_identity_with_secret(secret, gateway_wg_public_key)?;
    let candidate = load_candidate_private_identity(
        secret,
        gateway_wg_public_key,
        transition.gateway_identity_epoch,
    )?;
    compose_private_identity(
        active,
        candidate,
        transition.next_gateway_tls_certificate.is_some(),
        transition.next_gateway_certificate.is_some(),
    )?;
    Ok(())
}

/// Makes a durably promoted registry generation the active sealed slot.
///
/// The caller persists the registry first. Replacing the active vault is then
/// atomic, so a power cut leaves either the outgoing vault or the composed new
/// one intact; the candidate vault and transition document remain available
/// for a retry until every active public file has followed successfully.
pub(crate) fn promote_candidate_identity(
    secret: &SecretKey,
    gateway: &aether::certificates::state::GatewayCertificateState,
    transition: &aether::certificates::gateway::GatewayIdentityTransition,
) -> Result<()> {
    validate_promoted_gateway_identity(gateway, transition)?;

    let gateway_wg_public_key = gateway.gateway_wg_public_key.to_base64();
    let active = load_active_private_identity_with_secret(secret, &gateway_wg_public_key)?;
    let candidate = load_candidate_private_identity(
        secret,
        &gateway_wg_public_key,
        transition.gateway_identity_epoch,
    )?;
    let promoted = compose_private_identity(
        active,
        candidate,
        transition.next_gateway_tls_certificate.is_some(),
        transition.next_gateway_certificate.is_some(),
    )?;
    let encoded = Zeroizing::new(
        serde_json::to_vec(&promoted).context("encoding the promoted gateway identity")?,
    );

    // The registry is already promoted. Only now may this atomic replacement
    // destroy the outgoing private slot (§11.1 step 9).
    SealedKeystore::new(
        PRIVATE_KEYSTORE_PATH,
        helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY,
    )
    .store(
        secret,
        &negotiation_identity_context(&gateway_wg_public_key),
        encoded.as_slice(),
    )
    .context("installing the promoted gateway private identity")?;
    write_public_atomic(
        Path::new(CERTIFICATE_PATH),
        gateway.active_gateway_tls_certificate.as_bytes(),
    )
    .context("installing the promoted gateway TLS certificate")?;
    write_public_atomic(
        Path::new(PQ_CERTIFICATE_PATH),
        &serde_json::to_vec_pretty(&gateway.active_gateway_certificate)
            .context("encoding the promoted gateway PQ certificate")?,
    )
    .context("installing the promoted gateway PQ certificate")
}

/// Checks the promoted epoch, gateway key and active leaf fingerprints
/// against the retained transition before opening either private slot.
pub(crate) fn validate_promoted_gateway_identity(
    gateway: &aether::certificates::state::GatewayCertificateState,
    transition: &aether::certificates::gateway::GatewayIdentityTransition,
) -> Result<()> {
    use aether::certificates::gateway::pq_certificate_fingerprint;

    anyhow::ensure!(
        gateway.active_gateway_identity_epoch == transition.gateway_identity_epoch,
        "the promoted registry is at gateway epoch {}, but the retained transition is for epoch {}",
        gateway.active_gateway_identity_epoch,
        transition.gateway_identity_epoch
    );
    anyhow::ensure!(
        gateway.gateway_wg_public_key == transition.gateway_wg_public_key,
        "the retained transition belongs to another gateway identity"
    );

    let expected_tls = transition.next_gateway_tls_certificate.as_ref().map_or(
        transition.active_gateway_tls_certificate_fingerprint,
        |certificate| certificate.fingerprint(),
    );
    anyhow::ensure!(
        gateway.active_tls_fingerprint().matches(&expected_tls),
        "the promoted TLS leaf does not match the retained transition"
    );
    let expected_pq = match &transition.next_gateway_certificate {
        Some(certificate) => pq_certificate_fingerprint(certificate)
            .context("fingerprinting the retained candidate PQ leaf")?,
        None => transition.active_gateway_certificate_fingerprint,
    };
    anyhow::ensure!(
        gateway.active_pq_fingerprint()?.matches(&expected_pq),
        "the promoted PQ leaf does not match the retained transition"
    );

    Ok(())
}

/// Destroys the candidate identity, private half first (spec §6.3, `aborted`).
///
/// The sealed key goes before the leaf that names it: the reverse order would
/// leave, on a failure between the two removals, private material on disk with
/// nothing left to say which decision it belonged to. Called only once the
/// registry has persisted the abort — a candidate destroyed ahead of that
/// write would be destroyed for a cancellation that was refused.
pub(crate) fn discard_candidate_identity() -> Result<()> {
    discard_candidate_identity_at(&next_private_keystore_path(), &next_certificate_path())
}

fn discard_candidate_identity_at(keystore_path: &Path, certificate_path: &Path) -> Result<()> {
    remove_if_present(keystore_path)?;
    remove_if_present(certificate_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidate_sealing_context_is_the_canonical_gateway_and_epoch_pair() {
        let context = candidate_identity_context("gateway-key", 0x0102_0304_0506_0708);
        let expected = helios_tpm::Context::new()
            .field("gateway_wg_public_key", b"gateway-key")
            .field(
                "gateway_identity_epoch",
                &0x0102_0304_0506_0708_u64.to_be_bytes(),
            );

        assert_eq!(context, expected);
    }

    #[test]
    fn candidate_sealing_context_cannot_be_reused_for_another_gateway_or_epoch() {
        let original = candidate_identity_context("gateway-key", 17);
        assert_ne!(original, candidate_identity_context("other-gateway", 17));
        assert_ne!(original, candidate_identity_context("gateway-key", 18));
    }

    #[test]
    fn stored_candidate_keeps_tls_rotation_presence_distinct_from_an_empty_key() {
        let pq_private_key = "pq-private-base64";
        let without_tls = StoredCandidateIdentity {
            pq_private_key: pq_private_key.into(),
            tls_private_key: None,
        };
        let encoded_without_tls = serde_json::to_vec(&without_tls).expect("serialize candidate");
        let decoded_without_tls: StoredCandidateIdentity =
            serde_json::from_slice(&encoded_without_tls).expect("deserialize candidate");
        assert_eq!(decoded_without_tls.pq_private_key, pq_private_key);
        assert_eq!(decoded_without_tls.tls_private_key, None);

        let with_empty_tls = StoredCandidateIdentity {
            pq_private_key: pq_private_key.into(),
            tls_private_key: Some(String::new()),
        };
        let encoded_with_empty_tls =
            serde_json::to_vec(&with_empty_tls).expect("serialize candidate");
        let decoded_with_empty_tls: StoredCandidateIdentity =
            serde_json::from_slice(&encoded_with_empty_tls).expect("deserialize candidate");
        assert_eq!(decoded_with_empty_tls.tls_private_key.as_deref(), Some(""));
        assert_ne!(
            decoded_without_tls.tls_private_key,
            decoded_with_empty_tls.tls_private_key
        );
    }

    #[test]
    fn generated_tls_leaf_matches_its_pkcs8_key() {
        let (private, leaf) =
            generate_candidate_tls(" gateway.example ").expect("generate candidate TLS identity");

        assert_tls_key_matches(&leaf, private.to_vec());
    }

    #[test]
    fn generating_tls_rejects_a_server_name_that_cannot_be_encoded_in_x509() {
        let Err(error) = generate_candidate_tls("gâtéway.example") else {
            panic!("the certificate requires an ASCII DNS name");
        };
        assert_eq!(
            error.to_string(),
            "server name is not valid for an X.509 certificate"
        );
    }

    pub(super) fn assert_tls_key_matches(leaf: &DerCertificate, tls_key: Vec<u8>) {
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

        let provider = rustls::crypto::ring::default_provider();
        rustls::sign::CertifiedKey::from_der(
            vec![leaf.as_bytes().to_vec().into()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(tls_key)),
            &provider,
        )
        .expect("the public leaf matches the private key")
        .keys_match()
        .expect("verify the leaf's public key");
    }

    #[test]
    fn reading_candidate_tls_distinguishes_absence_from_invalid_or_unreadable_files() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let certificate = directory.path().join("candidate.der");

        assert!(read_candidate_tls_certificate(&certificate)
            .expect("missing file")
            .is_none());
        std::fs::write(&certificate, []).expect("write empty file");
        let error = read_candidate_tls_certificate(&certificate).expect_err("empty certificate");
        assert!(error
            .downcast_ref::<aether::certificates::CertificateError>()
            .is_some());
        assert!(read_candidate_tls_certificate(directory.path())
            .expect_err("directory instead of a certificate")
            .downcast_ref::<std::io::Error>()
            .is_some());
    }

    #[test]
    fn discarding_clears_the_candidate_and_is_idempotent() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let keystore = directory.path().join("candidate.sealed");
        let certificate = directory.path().join("candidate.der");
        std::fs::write(&keystore, b"sealed fixture").expect("create test vault");
        std::fs::write(&certificate, b"certificate fixture").expect("create test certificate");

        discard_candidate_identity_at(&keystore, &certificate).expect("remove candidate files");
        assert!(!keystore.exists());
        assert!(!certificate.exists());
        discard_candidate_identity_at(&keystore, &certificate).expect("discard again");
    }

    #[test]
    fn discarding_preserves_the_leaf_if_the_private_slot_cannot_be_removed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let keystore = directory.path().join("candidate.sealed");
        let certificate = directory.path().join("candidate.der");
        let leaf = b"candidate certificate fixture";
        std::fs::create_dir(&keystore).expect("block private file removal");
        std::fs::write(&certificate, leaf).expect("create test certificate");

        let error = discard_candidate_identity_at(&keystore, &certificate)
            .expect_err("cannot remove the private file");
        assert_eq!(
            error.to_string(),
            format!("removing {}", keystore.display())
        );
        assert_eq!(
            std::fs::read(&certificate).expect("read retained certificate"),
            leaf
        );
    }

    #[test]
    fn discarding_can_retry_after_the_private_slot_is_removed() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let keystore = directory.path().join("candidate.sealed");
        let certificate = directory.path().join("candidate.der");
        std::fs::write(&keystore, b"sealed fixture").expect("create test vault");
        std::fs::create_dir(&certificate).expect("block public file removal");

        let error = discard_candidate_identity_at(&keystore, &certificate)
            .expect_err("cannot remove the public file");
        assert_eq!(
            error.to_string(),
            format!("removing {}", certificate.display())
        );
        assert!(!keystore.exists());

        std::fs::remove_dir(&certificate).expect("unblock certificate removal");
        std::fs::write(&certificate, b"certificate fixture").expect("create test certificate");
        discard_candidate_identity_at(&keystore, &certificate).expect("retry candidate removal");
        assert!(!certificate.exists());
    }

    #[test]
    fn stored_candidate_rejects_unknown_fields_and_missing_pq_material() {
        for malformed in [
            br#"{"pq_private_key":"pq","tls_private_key":null,"extra":true}"#.as_slice(),
            br#"{"tls_private_key":null}"#.as_slice(),
        ] {
            assert!(
                serde_json::from_slice::<StoredCandidateIdentity>(malformed).is_err(),
                "malformed candidate record should be refused"
            );
        }
    }
}

#[cfg(all(test, not(feature = "tpm")))]
mod sealed_slot_tests {
    use super::*;
    use aether::certificates::{
        encoding::{Id16, MlDsa87PublicKey, MlDsa87Signature, TrustDomainId, WireGuardKey},
        gateway::{Continuity, GatewayCertificateRequest},
        CERTIFICATE_FORMAT_VERSION,
    };
    use std::path::PathBuf;

    const SERVER_NAME: &str = "gateway.example";
    const EPOCH: u64 = 17;
    const NOW: u64 = 1_700_000_000;

    struct Slot {
        _directory: tempfile::TempDir,
        secret: SecretKey,
        gateway_key: WireGuardKey,
        keystore: PathBuf,
        certificate: PathBuf,
    }

    impl Slot {
        fn new() -> Self {
            let directory = tempfile::tempdir().expect("temporary candidate directory");
            let path = |name| directory.path().join(name);
            let settings = helios_tpm::TpmSettings {
                enabled: true,
                allow_provisioning: true,
                device: path("no-tpm-device").to_string_lossy().into_owned(),
                sealed_blob_path: path("simulated-root").to_string_lossy().into_owned(),
                ticket_path: path("ticket").to_string_lossy().into_owned(),
                state_path: path("state").to_string_lossy().into_owned(),
                update_window_marker_path: path("window").to_string_lossy().into_owned(),
                ..helios_tpm::TpmSettings::default()
            };
            let decision = helios_tpm::BootController::unlock(&settings)
                .expect("provision secret with the simulated TPM");
            Self {
                secret: decision.secret().expect("simulated secret").clone(),
                gateway_key: WireGuardKey::from_bytes([9; 32]),
                keystore: path("candidate.sealed"),
                certificate: path("candidate.der"),
                _directory: directory,
            }
        }

        fn seal(&self, rotate_tls: bool) -> Result<SealedCandidate> {
            seal_candidate_identity_at(
                &self.secret,
                &self.gateway_key.to_base64(),
                SERVER_NAME,
                EPOCH,
                rotate_tls,
                &self.keystore,
                &self.certificate,
            )
        }

        fn store(&self) -> SealedKeystore {
            SealedKeystore::new(&self.keystore, helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY)
        }

        fn read_private(&self) -> StoredCandidateIdentity {
            let context = candidate_identity_context(&self.gateway_key.to_base64(), EPOCH);
            let encoded = self.store().load(&self.secret, &context).expect("unseal");
            serde_json::from_slice(&encoded).expect("decode private candidate")
        }

        fn request(&self, pq_public_key: MlDsa87PublicKey) -> GatewayCertificateRequest {
            GatewayCertificateRequest {
                format_version: CERTIFICATE_FORMAT_VERSION,
                trust_domain_id: TrustDomainId::new([1; 16]).expect("domain"),
                gateway_identity_epoch: EPOCH,
                gateway_wg_public_key: self.gateway_key,
                server_name: SERVER_NAME.into(),
                new_ml_dsa_87_public_key: pq_public_key,
                request_id: Id16::new([7; 16]).expect("id"),
                created_at: NOW,
                expires_at: NOW + 3_600,
                new_key_proof: MlDsa87Signature::placeholder(),
                current_key_authorization: None,
            }
        }
    }

    #[test]
    fn sealing_tls_writes_a_leaf_matching_the_private_key_then_pq_only_replaces_the_candidate() {
        let slot = Slot::new();
        let sealed = slot.seal(true).expect("seal TLS and PQ keys");
        let leaf = sealed.tls_certificate.expect("candidate TLS certificate");
        assert_eq!(
            read_candidate_tls_certificate(&slot.certificate).expect("read public leaf"),
            Some(leaf.clone())
        );

        let private = slot.read_private();
        let tls_key = base64::engine::general_purpose::STANDARD
            .decode(private.tls_private_key.as_deref().expect("TLS private key"))
            .expect("decode TLS key");
        tests::assert_tls_key_matches(&leaf, tls_key);

        let replacement = slot.seal(false).expect("seal replacement PQ key only");
        assert_ne!(replacement.pq_public_key, sealed.pq_public_key);
        assert!(replacement.tls_certificate.is_none());
        assert!(slot.read_private().tls_private_key.is_none());
        assert!(!slot.certificate.exists());
    }

    #[test]
    fn sealing_failure_cannot_replace_the_public_leaf() {
        let slot = Slot::new();
        let leaf = slot.seal(true).expect("first preparation").tls_certificate;
        std::fs::remove_file(&slot.keystore).expect("remove test vault");
        std::fs::create_dir(&slot.keystore).expect("block writes at the vault path");

        let Err(error) = slot.seal(true) else {
            panic!("sealing must fail");
        };

        assert_eq!(error.to_string(), "sealing the candidate gateway keys");
        assert_eq!(
            read_candidate_tls_certificate(&slot.certificate).expect("read previous leaf"),
            leaf
        );
    }

    #[test]
    fn a_failed_public_install_leaves_the_private_candidate_sealed() {
        let slot = Slot::new();
        std::fs::create_dir(&slot.certificate).expect("block publication");

        let Err(error) = slot.seal(true) else {
            panic!("publication must fail");
        };

        assert_eq!(
            error.to_string(),
            "installing the candidate gateway TLS certificate"
        );
        assert!(slot.read_private().tls_private_key.is_some());
    }

    #[test]
    fn recovery_proves_possession_without_faking_active_key_continuity() {
        let slot = Slot::new();
        let sealed = slot.seal(false).expect("seal PQ key");
        let request = slot.request(sealed.pq_public_key);
        let signed = sign_certificate_request_at(
            request,
            Some(&slot.secret),
            false,
            &slot.gateway_key.to_base64(),
            EPOCH,
            RequestContinuity::KeyRecovery,
            &slot.keystore,
        )
        .expect("sign using the sealed candidate only");

        assert!(signed.current_key_authorization.is_none());
        signed
            .verify(
                Continuity::WaivedForKeyRecovery,
                &signed.trust_domain_id,
                EPOCH - 1,
                &slot.gateway_key,
                SERVER_NAME,
                NOW,
            )
            .expect("the candidate proof verifies against the public key");
    }

    #[test]
    fn signing_refuses_to_open_the_slot_for_another_gateway_or_epoch() {
        let slot = Slot::new();
        let sealed = slot.seal(false).expect("seal PQ key");
        let request = slot.request(sealed.pq_public_key);

        for (gateway_key, epoch) in [
            (WireGuardKey::from_bytes([8; 32]), EPOCH),
            (slot.gateway_key, EPOCH + 1),
        ] {
            let error = sign_certificate_request_at(
                request.clone(),
                Some(&slot.secret),
                false,
                &gateway_key.to_base64(),
                epoch,
                RequestContinuity::KeyRecovery,
                &slot.keystore,
            )
            .expect_err("the slot belongs to the original gateway and epoch");
            assert_eq!(
                error.to_string(),
                "unsealing the candidate gateway identity"
            );
        }
    }

    #[test]
    fn signing_distinguishes_malformed_candidate_records_from_missing_unlock_secret() {
        let slot = Slot::new();
        let sealed = slot.seal(false).expect("seal PQ key");
        let request = slot.request(sealed.pq_public_key);
        let gateway_key = slot.gateway_key.to_base64();
        let context = candidate_identity_context(&gateway_key, EPOCH);
        let sign = |secret| {
            sign_certificate_request_at(
                request.clone(),
                secret,
                true,
                &gateway_key,
                EPOCH,
                RequestContinuity::KeyRecovery,
                &slot.keystore,
            )
            .expect_err("refuse to sign")
        };
        assert_eq!(
            sign(None).to_string(),
            "TPM secret unavailable: the candidate gateway identity stays sealed"
        );
        for (record, error) in [
            (
                br#"{"pq_private_key":42}"#.as_slice(),
                "decoding the candidate gateway identity",
            ),
            (
                br#"{"pq_private_key":"!"}"#.as_slice(),
                "decoding the candidate gateway PQ private key",
            ),
            (
                br#"{"pq_private_key":"AA=="}"#.as_slice(),
                "signing the gateway certificate request",
            ),
        ] {
            slot.store()
                .store(&slot.secret, &context, record)
                .expect("install malformed candidate");
            assert_eq!(sign(Some(&slot.secret)).to_string(), error);
        }
    }
}
