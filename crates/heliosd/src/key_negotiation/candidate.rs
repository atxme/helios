//! The candidate identity of a gateway rotation: sealing, promotion and
//! discard.

use super::*;

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
    use aether::certificates::encoding::{DerCertificate, MlDsa87PublicKey};
    use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose};

    let (pq_private_key, pq_public_key) =
        generate_ml_dsa_87_keypair().context("generating the candidate gateway PQ identity")?;

    let tls = if rotate_tls {
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
        Some((Zeroizing::new(key_pair.serialize_der()), der))
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
    SealedKeystore::new(
        next_private_keystore_path(),
        helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY,
    )
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
            write_public_atomic(&next_certificate_path(), der.as_bytes())
                .context("installing the candidate gateway TLS certificate")?;
            Some(der)
        }
        None => {
            // A previous attempt may have rotated TLS where this one does not.
            remove_if_present(&next_certificate_path())?;
            None
        }
    };

    Ok(SealedCandidate {
        pq_public_key: MlDsa87PublicKey::new(pq_public_key.to_vec())
            .context("encoding the candidate gateway PQ public key")?,
        tls_certificate,
    })
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
    let unsealing =
        secret.context("TPM secret unavailable: the candidate gateway identity stays sealed")?;
    let sealed = SealedKeystore::new(
        next_private_keystore_path(),
        helios_tpm::DOMAIN_KEY_NEGOTIATION_IDENTITY,
    )
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
    use aether::certificates::encoding::DerCertificate;

    match std::fs::read(next_certificate_path()) {
        Ok(der) => Ok(Some(DerCertificate::new(der).with_context(|| {
            format!("reading {}", next_certificate_path().display())
        })?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            Err(error).with_context(|| format!("reading {}", next_certificate_path().display()))
        }
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

/// Destroys the candidate identity, private half first (spec §6.3, `aborted`).
///
/// The sealed key goes before the leaf that names it: the reverse order would
/// leave, on a failure between the two removals, private material on disk with
/// nothing left to say which decision it belonged to. Called only once the
/// registry has persisted the abort — a candidate destroyed ahead of that
/// write would be destroyed for a cancellation that was refused.
pub(crate) fn discard_candidate_identity() -> Result<()> {
    remove_if_present(&next_private_keystore_path())?;
    remove_if_present(&next_certificate_path())
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
