//! The per-peer queue of pre-signed transactions the authority leaves here.
//!
//! The gateway stores and hands over; it signs nothing and verifies nothing
//! it could not verify under an anchor it already holds.

use super::{
    CertificateError, CertificateRegistry, Fingerprint, Id16, PendingDistribution, RegistryError,
    TrustUpdateChunk, TrustUpdateTransactionManifest, WireGuardKey,
};

impl CertificateRegistry {
    /// Accepts a pre-signed transaction the authority left for one peer.
    ///
    /// # What is checked here, and what deliberately is not
    ///
    /// The gateway verifies that the transaction **addresses this domain and
    /// this peer**, that its fragments are the ones the manifest names, and
    /// that it has not already expired. It does **not** verify the manifest's
    /// signature or the objects inside it — it holds neither `CA-PQ` nor the
    /// service key, and a verification it cannot complete is worse than none:
    /// it would have to be written against whichever authority happened to be
    /// available, and that is exactly the check an attacker chooses.
    ///
    /// The receiver verifies, under anchors it already trusts. That is the
    /// whole shape of §8.1: an object is authorized by what the receiver holds,
    /// never by the envelope that delivered it — and here the gateway *is* the
    /// envelope.
    ///
    /// Replacing an undrained transaction is allowed and is the point: a newer
    /// decision supersedes an older one, and a client that never came back for
    /// its fragments must not pin the queue.
    pub fn stage_distribution(
        &mut self,
        wg_public_key: &WireGuardKey,
        manifest: TrustUpdateTransactionManifest,
        chunks: Vec<TrustUpdateChunk>,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        let mut state = self.state.clone();
        if manifest.trust_domain_id != state.trust_domain_id {
            return Err(RegistryError::Certificate(
                CertificateError::TrustDomainMismatch,
            ));
        }
        if manifest.gateway_wg_public_key != state.gateway.gateway_wg_public_key {
            return Err(RegistryError::Certificate(
                CertificateError::GatewayIdentityMismatch,
            ));
        }
        if manifest.client_wg_public_key != *wg_public_key {
            return Err(RegistryError::Certificate(
                CertificateError::ClientIdentityMismatch,
            ));
        }
        if now_unix >= manifest.expires_at {
            return Err(RegistryError::Certificate(CertificateError::StageExpired));
        }
        if chunks.len() != usize::from(manifest.chunk_count) || chunks.is_empty() {
            return Err(RegistryError::Certificate(CertificateError::MissingProof(
                "transaction fragments",
            )));
        }
        // Each fragment must be the one the manifest expects at that index.
        // Serving a fragment the manifest does not cover would have the client
        // refuse the whole transaction after collecting all of it — a failure
        // that costs a full poll cycle to discover.
        let manifest_fingerprint = manifest.fingerprint();
        for (index, chunk) in chunks.iter().enumerate() {
            if usize::from(chunk.chunk_index) != index
                || chunk.chunk_count != manifest.chunk_count
                || !chunk.manifest_fingerprint.matches(&manifest_fingerprint)
            {
                return Err(RegistryError::Certificate(CertificateError::MissingProof(
                    "transaction fragment",
                )));
            }
        }

        let peer = state
            .peers
            .get_mut(&wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        peer.distribution = Some(PendingDistribution {
            manifest,
            chunks,
            cursor: 0,
            last_request_id: None,
        });
        self.persist(state)
    }

    /// The fragment this request is owed, if any.
    ///
    /// Returns the manifest alongside the fragment on **every** call and not
    /// only the first: a client that lost its copy between two polls would
    /// otherwise hold fragments it cannot attribute, and §8.1.1 has it refuse
    /// exactly that. Sending it again costs one signed object on a route that
    /// is already carrying the fragment.
    pub fn take_distribution_chunk(
        &mut self,
        wg_public_key: &WireGuardKey,
        request_id: &Id16,
        base_state_fingerprint: &Fingerprint,
        now_unix: u64,
    ) -> Result<Option<(TrustUpdateTransactionManifest, TrustUpdateChunk)>, RegistryError> {
        let mut state = self.state.clone();
        let peer = state
            .peers
            .get_mut(&wg_public_key.to_base64())
            .ok_or(RegistryError::UnknownPeer)?;
        let Some(distribution) = peer.distribution.as_mut() else {
            return Ok(None);
        };
        // An expired transaction is dropped rather than served: past
        // `expires_at` the receiver refuses it, and handing it over would burn
        // a poll cycle to reach that refusal.
        if now_unix >= distribution.manifest.expires_at {
            peer.distribution = None;
            self.persist(state)?;
            return Ok(None);
        }
        // A transaction is a compare-and-swap decision for the exact local
        // state the client signed. Serving one built for an older snapshot
        // would spend a complete chunk cycle only to be refused at commit.
        // Drop it so the preparation relay can replace it from this request.
        if !distribution
            .manifest
            .base_state_fingerprint
            .matches(base_state_fingerprint)
        {
            peer.distribution = None;
            self.persist(state)?;
            return Ok(None);
        }
        let manifest = distribution.manifest.clone();
        let served = distribution
            .serve(request_id)
            .map(|chunk| (manifest, chunk.clone()));
        // Kept until it is drained **and** re-asked for: dropping it on the
        // last fragment would leave a client whose final poll was lost with no
        // way to ask again.
        let drained = distribution.drained();
        if served.is_none() && drained {
            peer.distribution = None;
        }
        self.persist(state)?;
        Ok(served)
    }
}
