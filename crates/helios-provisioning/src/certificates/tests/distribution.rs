use super::*;

/// A COSE ES256 public key, as an authenticator publishes one. The
/// binding's own verification parses this field, so a placeholder would
/// pass a test the real exchange refuses.
fn cose_es256_key() -> Vec<u8> {
    let mut key = vec![0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    key.extend_from_slice(&[3u8; 32]);
    key.extend_from_slice(&[0x22, 0x58, 0x20]);
    key.extend_from_slice(&[5u8; 32]);
    key
}

fn credential_row(
    ca: &Keys,
    credential_id: Vec<u8>,
) -> aether::certificates::approval::AstraCredentialBinding {
    aether::certificates::approval::AstraCredentialBinding {
        format_version: aether::certificates::CERTIFICATE_FORMAT_VERSION,
        credential_id,
        credential_public_key: cose_es256_key(),
        aaguid: [0; 16],
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        state: aether::certificates::approval::CredentialState::Active,
        credential_epoch: 1,
        credential_registry_epoch: 1,
        ca_epoch: 1,
        created_at: 1_000,
        ca_pq_signature: MlDsa87Signature::placeholder(),
    }
    .sign(&ca.private)
    .expect("signed under CA-PQ")
}

fn credential_document(
    rows: Vec<aether::certificates::approval::AstraCredentialBinding>,
) -> aether::certificates::approval::CredentialRegistry {
    aether::certificates::approval::CredentialRegistry {
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        ca_epoch: 1,
        credential_registry_epoch: 1,
        bindings: rows,
    }
}

/// The gateway distributes the operator credentials it never uses: the
/// §19 enrolment block is all a client reads before it has a tunnel, and
/// §7.5 begins by naming the credential that will approve the recovery.
#[test]
fn the_operator_credentials_are_recorded_for_the_enrolment_to_carry() {
    let mut fixture = fixture();
    let document = credential_document(vec![
        credential_row(&fixture.ca, vec![0xAB, 0xCD]),
        credential_row(&fixture.ca, vec![0x01, 0x02]),
    ]);

    assert_eq!(
        fixture
            .registry
            .install_astra_credentials(&document)
            .expect("recorded"),
        2
    );
    assert_eq!(
        fixture.registry.state().astra.credential_bindings.len(),
        2,
        "both rows reach the state the enrolment view reads"
    );
    assert_eq!(
        fixture
            .registry
            .install_astra_credentials(&document)
            .expect("idempotent"),
        0,
        "replaying the same document installs nothing again"
    );
}

/// One forged row beside honest ones rejects the whole document. It is
/// that row a later `supersedes` would be compared against, so installing
/// its neighbours and skipping it would leave the registry worse than
/// untouched.
#[test]
fn a_document_carrying_one_unsigned_row_is_refused_whole() {
    let mut fixture = fixture();
    let stranger = keys();
    let document = credential_document(vec![
        credential_row(&fixture.ca, vec![0xAB, 0xCD]),
        credential_row(&stranger, vec![0x01, 0x02]),
    ]);

    assert!(fixture
        .registry
        .install_astra_credentials(&document)
        .is_err());
    assert!(
        fixture
            .registry
            .state()
            .astra
            .credential_bindings
            .is_empty(),
        "a refused document installs none of its rows"
    );
}
/// A transaction as the authority signs one. The signature is never
/// checked here — the gateway holds no authority key, and that is the
/// point of these tests — so a placeholder is exactly right.
pub(super) fn distribution(
    client: &WireGuardKey,
    chunk_count: u16,
    expires_at: u64,
) -> (TrustUpdateTransactionManifest, Vec<TrustUpdateChunk>) {
    let manifest = TrustUpdateTransactionManifest {
        format_version: CERTIFICATE_FORMAT_VERSION,
        protocol_version: CERTIFICATE_PROTOCOL_VERSION,
        transaction_id: Id16::new([9; 16]).expect("id"),
        trust_domain_id: domain(),
        gateway_wg_public_key: gateway_key(),
        client_wg_public_key: *client,
        base_state_fingerprint: Fingerprint::of(b"base state"),
        created_at: 0,
        expires_at,
        minimum_activation_at: expires_at,
        chunk_count,
        objects: Vec::new(),
        manifest_authority_kind:
            aether::certificates::transport::ManifestAuthority::AstraServiceKey,
        manifest_authority_epoch: 1,
        signature: MlDsa87Signature::placeholder(),
    };
    let manifest_fingerprint = manifest.fingerprint();
    let chunks = (0..chunk_count)
        .map(|index| TrustUpdateChunk {
            manifest_fingerprint,
            chunk_index: index,
            chunk_count,
            first_object_index: index,
            objects: Vec::new(),
        })
        .collect();
    (manifest, chunks)
}

/// The fragments come back in order, one per fresh request, and the
/// manifest travels with every one of them.
#[test]
fn a_queued_transaction_is_served_one_fragment_per_request() {
    let mut fixture = fixture();
    let (manifest, chunks) = distribution(&client_key(2), 3, 10_000);
    fixture
        .registry
        .stage_distribution(&client_key(2), manifest, chunks, 0)
        .expect("queued");

    for index in 0..3u16 {
        let request = Id16::new([index as u8 + 1; 16]).expect("request id");
        let (manifest, chunk) = fixture
            .registry
            .take_distribution_chunk(&client_key(2), &request, &Fingerprint::of(b"base state"), 0)
            .expect("readable")
            .expect("a fragment is owed");
        assert_eq!(chunk.chunk_index, index);
        assert_eq!(
            chunk.manifest_fingerprint,
            manifest.fingerprint(),
            "a client must be able to attribute every fragment it holds"
        );
    }

    // Drained: nothing more is owed, and the queue stops answering.
    let last = Id16::new([99; 16]).expect("request id");
    assert!(fixture
        .registry
        .take_distribution_chunk(&client_key(2), &last, &Fingerprint::of(b"base state"), 0,)
        .expect("readable")
        .is_none());
}

/// A retransmission gets the fragment it already got. Advancing on a
/// replay would skip one over a lossy link, and the client would poll
/// forever for a transaction it can never complete.
#[test]
fn a_repeated_request_is_served_the_same_fragment() {
    let mut fixture = fixture();
    let (manifest, chunks) = distribution(&client_key(2), 2, 10_000);
    fixture
        .registry
        .stage_distribution(&client_key(2), manifest, chunks, 0)
        .expect("queued");

    let request = Id16::new([7; 16]).expect("request id");
    let first = fixture
        .registry
        .take_distribution_chunk(&client_key(2), &request, &Fingerprint::of(b"base state"), 0)
        .expect("readable")
        .expect("owed")
        .1;
    let replayed = fixture
        .registry
        .take_distribution_chunk(&client_key(2), &request, &Fingerprint::of(b"base state"), 0)
        .expect("readable")
        .expect("owed")
        .1;
    assert_eq!(first.chunk_index, 0);
    assert_eq!(replayed.chunk_index, 0);
}

/// Past its deadline the receiver refuses the whole transaction, so
/// handing it over would only spend a poll cycle reaching that refusal.
#[test]
fn an_expired_transaction_is_dropped_rather_than_served() {
    let mut fixture = fixture();
    let (manifest, chunks) = distribution(&client_key(2), 1, 1_000);
    fixture
        .registry
        .stage_distribution(&client_key(2), manifest, chunks, 0)
        .expect("queued");

    let request = Id16::new([7; 16]).expect("request id");
    assert!(fixture
        .registry
        .take_distribution_chunk(
            &client_key(2),
            &request,
            &Fingerprint::of(b"base state"),
            1_000,
        )
        .expect("readable")
        .is_none());
    assert!(
        fixture
            .registry
            .peer(&client_key(2))
            .expect("peer")
            .distribution
            .is_none(),
        "an expired transaction does not stay in the queue"
    );
}

/// The queue is only transport: it must not hand a client a decision
/// computed for a state other than the one this request signed.
#[test]
fn a_transaction_for_another_base_state_is_dropped() {
    let mut fixture = fixture();
    let (manifest, chunks) = distribution(&client_key(2), 1, 10_000);
    fixture
        .registry
        .stage_distribution(&client_key(2), manifest, chunks, 0)
        .expect("queued");

    let request = Id16::new([7; 16]).expect("request id");
    assert!(fixture
        .registry
        .take_distribution_chunk(
            &client_key(2),
            &request,
            &Fingerprint::of(b"new local state"),
            0,
        )
        .expect("readable")
        .is_none());
    assert!(fixture
        .registry
        .peer(&client_key(2))
        .expect("peer")
        .distribution
        .is_none());
}

/// A transaction addressed elsewhere is refused. The manifest names its
/// target and the signature covers that name: queueing it under another
/// peer would hand one client a decision signed for another.
#[test]
fn a_transaction_for_another_peer_is_refused() {
    let mut fixture = fixture();
    let (manifest, chunks) = distribution(&client_key(3), 1, 10_000);
    assert!(matches!(
        fixture
            .registry
            .stage_distribution(&client_key(2), manifest, chunks, 0),
        Err(RegistryError::Certificate(
            CertificateError::ClientIdentityMismatch
        ))
    ));
}

/// A fragment set that does not match the manifest is refused at the door.
/// Accepting it would have the client collect everything and only then
/// refuse — a full poll cycle spent to discover a fault the gateway could
/// see immediately.
#[test]
fn a_fragment_set_that_contradicts_its_manifest_is_refused() {
    let mut fixture = fixture();
    let (manifest, mut chunks) = distribution(&client_key(2), 2, 10_000);
    chunks.pop();
    assert!(fixture
        .registry
        .stage_distribution(&client_key(2), manifest.clone(), chunks, 0)
        .is_err());

    let (_, mut reordered) = distribution(&client_key(2), 2, 10_000);
    reordered.reverse();
    assert!(fixture
        .registry
        .stage_distribution(&client_key(2), manifest, reordered, 0)
        .is_err());
}

/// A newer decision supersedes an older one. A client that never came back
/// for its fragments must not pin the queue against the authority.
#[test]
fn a_newer_transaction_replaces_one_left_undrained() {
    let mut fixture = fixture();
    let (first, first_chunks) = distribution(&client_key(2), 3, 10_000);
    fixture
        .registry
        .stage_distribution(&client_key(2), first, first_chunks, 0)
        .expect("queued");
    let (second, second_chunks) = distribution(&client_key(2), 1, 20_000);
    let expected = second.fingerprint();
    fixture
        .registry
        .stage_distribution(&client_key(2), second, second_chunks, 0)
        .expect("replaced");

    let request = Id16::new([7; 16]).expect("request id");
    let (manifest, chunk) = fixture
        .registry
        .take_distribution_chunk(&client_key(2), &request, &Fingerprint::of(b"base state"), 0)
        .expect("readable")
        .expect("owed");
    assert_eq!(manifest.fingerprint(), expected);
    assert_eq!(chunk.chunk_count, 1);
}
