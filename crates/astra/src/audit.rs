//! Hash-chained audit log.
//!
//! Every mutation of the registry appends a record whose hash covers the
//! previous one. That does not stop `root` from rewriting the file — nothing
//! co-located with the gateway can (ADR-008, *Conséquences*) — but it makes a
//! **fork** detectable: a restore from backup that disagrees with the last
//! known head is refused instead of silently continuing a second history.
//!
//! That is the property the specification actually asks for: "la restauration
//! doit vérifier le dernier hash d'audit connu et refuser un fork de
//! génération". An append-only file that anyone can truncate still tells you,
//! afterwards, that it was truncated.

use aether::certificates::encoding::Fingerprint;
use serde::{Deserialize, Serialize};

const AUDIT_DOMAIN: &[u8] = b"helios-astra-audit-v5";

/// What an audit record describes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEvent {
    DomainBootstrapped,
    /// One peer transcribed from the gateway's admission, at its first
    /// generation. Astra records who it was told about; it never decides it.
    PeerAdmitted {
        peer: String,
        generation: u64,
    },
    IssuerInstalled {
        issuer_epoch: u64,
    },
    /// The domain left the superseded per-request issuance policy for the
    /// current one, on the evidence of a `CA-PQ`-signed delegation.
    IssuancePolicyAdopted {
        policy_fingerprint: String,
    },
    IssuerRevoked {
        issuer_epoch: u64,
    },
    ClientRenewalRequested {
        peer: String,
        generation: u64,
    },
    ClientStageAuthorized {
        peer: String,
        generation: u64,
    },
    ClientGrantReleased {
        peer: String,
        generation: u64,
    },
    ClientStagePurged {
        peer: String,
        generation: u64,
    },
    ExpiredRecoveryApproved {
        peer: String,
        generation: u64,
    },
    CampaignCreated {
        campaign: String,
        targets: usize,
    },
    CampaignApproved {
        campaign: String,
    },
    /// Anchor transitions an approved campaign produced, now held for
    /// delivery. Recorded by count and campaign: the objects themselves are
    /// in the registry, and duplicating them here would make the chain the
    /// second place a transition is stored.
    AnchorTransitionsAccepted {
        campaign: String,
        objects: usize,
    },
    CampaignRefused {
        campaign: String,
        reason: String,
    },
    CertificateRevoked {
        target: String,
    },
    ServiceKeyRotated {
        epoch: u64,
    },
    /// The client `CA-TLS` in service was recorded, once (spec §9.4).
    ClientTlsCaPinned {
        ca_tls_epoch: u64,
    },
    /// A staged gateway transition may now leave (spec §6.3). Recorded
    /// because the moment is irreversible: after it, no abort is legitimate,
    /// and an audit that could not date it could not tell a late abort from
    /// an early one.
    GatewayTransitionPublished {
        gateway_identity_epoch: u64,
    },
    StatusPublished {
        target: String,
        status_epoch: u64,
    },
    /// A peer's generation, as the gateway serves it, was adopted here.
    ///
    /// Distinct from [`Self::ExpiredRecoveryApproved`] on purpose: that one
    /// records that an operator's proof was **accepted**, this one that the
    /// generation it unlocked is now the one this registry names. A recovery
    /// that stopped between the two is exactly what the pair is meant to make
    /// visible, and a single event could not tell the halves apart.
    PeerGenerationAdopted {
        peer: String,
        generation: u64,
    },
}

impl AuditEvent {
    /// Whether this event changed **what the authority may do**.
    ///
    /// The operator witness pins the authority's own configuration: its
    /// anchors, its delegation, its policy, the campaigns it approved. Those
    /// are what a restore could resurrect, so a chain that moved past the
    /// witness on one of them is refused until an operator records the new
    /// head — and an operator was, by construction, present when it happened.
    ///
    /// Per-peer lifecycle is the other half, and it is not the same thing. A
    /// peer admitted, renewed, staged or recovered widens nothing: the
    /// authority's powers are identical before and after. Those records are
    /// appended unattended, at any hour, by clients nobody is watching —
    /// requiring a fresh witness for them would mean requiring an operator to
    /// be present for every renewal, which is precisely what §8.1.2 removed.
    pub fn changes_authority_configuration(&self) -> bool {
        match self {
            Self::DomainBootstrapped
            | Self::IssuerInstalled { .. }
            | Self::IssuancePolicyAdopted { .. }
            | Self::IssuerRevoked { .. }
            | Self::CampaignApproved { .. }
            | Self::CampaignRefused { .. }
            | Self::AnchorTransitionsAccepted { .. }
            | Self::CertificateRevoked { .. }
            | Self::ServiceKeyRotated { .. }
            | Self::ClientTlsCaPinned { .. }
            | Self::GatewayTransitionPublished { .. } => true,
            Self::PeerAdmitted { .. }
            | Self::PeerGenerationAdopted { .. }
            | Self::ClientRenewalRequested { .. }
            | Self::ClientStageAuthorized { .. }
            | Self::ClientGrantReleased { .. }
            | Self::ClientStagePurged { .. }
            | Self::ExpiredRecoveryApproved { .. }
            | Self::CampaignCreated { .. }
            | Self::StatusPublished { .. } => false,
        }
    }
}

/// One link of the chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditRecord {
    pub sequence: u64,
    pub recorded_at: u64,
    pub event: AuditEvent,
    /// Hash of the previous record, all-zero for the first.
    pub previous: Fingerprint,
    pub digest: Fingerprint,
}

/// What a chain grew by since the operator wrote its witness down.
///
/// Returned rather than swallowed: an operator restarting Astra is entitled to
/// know that eleven client records were appended since they last looked, and a
/// silent acceptance would make the witness feel checked when nothing about
/// those records was ever attested.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WitnessGrowth {
    pub witnessed_sequence: u64,
    pub appended: usize,
}

/// The chain itself.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditChain {
    pub records: Vec<AuditRecord>,
}

impl AuditChain {
    /// Digest of the last record, or all-zero on an empty chain.
    pub fn head(&self) -> Fingerprint {
        self.records
            .last()
            .map(|record| record.digest)
            .unwrap_or_else(|| Fingerprint::from_bytes([0; 32]))
    }

    pub fn append(&mut self, event: AuditEvent, recorded_at: u64) -> &AuditRecord {
        let previous = self.head();
        let sequence = self.records.len() as u64;
        let digest = Self::digest(sequence, recorded_at, &event, &previous);
        self.records.push(AuditRecord {
            sequence,
            recorded_at,
            event,
            previous,
            digest,
        });
        self.records.last().expect("just pushed")
    }

    /// Recomputes the whole chain and, optionally, checks it continues a known
    /// head.
    ///
    /// `expected_head` is what makes a restore safe: a backup that verifies
    /// internally but ends on a different digest than the one the operator
    /// recorded is a fork, and continuing it would sign two histories.
    pub fn verify(&self, expected_head: Option<&Fingerprint>) -> Result<(), AuditError> {
        let mut previous = Fingerprint::from_bytes([0; 32]);
        for (index, record) in self.records.iter().enumerate() {
            if record.sequence != index as u64 {
                return Err(AuditError::OutOfOrder {
                    sequence: index as u64,
                });
            }
            if !record.previous.matches(&previous) {
                return Err(AuditError::Broken {
                    sequence: record.sequence,
                });
            }
            let digest = Self::digest(
                record.sequence,
                record.recorded_at,
                &record.event,
                &record.previous,
            );
            if !record.digest.matches(&digest) {
                return Err(AuditError::Broken {
                    sequence: record.sequence,
                });
            }
            previous = record.digest;
        }
        if let Some(expected) = expected_head {
            if !previous.matches(expected) {
                return Err(AuditError::Forked);
            }
        }
        Ok(())
    }

    /// Verifies a recorded operator witness that the chain has since grown
    /// past, and reports what grew.
    ///
    /// # Why an ancestor is accepted, and where the line is drawn
    ///
    /// A witness is a digest an operator wrote down. It can only ever speak
    /// about the history that existed when it was captured: events appended
    /// afterwards are, arithmetically, outside what it attests. Demanding
    /// strict equality therefore does not make the witness stronger — it makes
    /// it require re-capture after every unattended client renewal, and a
    /// witness re-captured by reading the very file it is meant to check
    /// attests nothing at all.
    ///
    /// So the witness must appear **in** the chain, which is what catches a
    /// restore that diverged before or at the recorded point, and the suffix
    /// after it is judged by what it did. Anything that changed the
    /// authority's configuration is refused: an operator was present when it
    /// happened and can record the new head, and those are exactly the records
    /// a rollback could use to resurrect a withdrawn anchor or delegation.
    /// Per-peer lifecycle is accepted and named in the returned report, so
    /// growth is visible rather than merely tolerated.
    pub fn verify_from_witness(&self, expected: &Fingerprint) -> Result<WitnessGrowth, AuditError> {
        self.verify(None)?;
        let Some(index) = self
            .records
            .iter()
            .position(|record| record.digest.matches(expected))
        else {
            return Err(AuditError::Forked);
        };
        let suffix = &self.records[index + 1..];
        if let Some(record) = suffix
            .iter()
            .find(|record| record.event.changes_authority_configuration())
        {
            return Err(AuditError::WitnessOutdated {
                sequence: record.sequence,
            });
        }
        Ok(WitnessGrowth {
            witnessed_sequence: self.records[index].sequence,
            appended: suffix.len(),
        })
    }

    fn digest(
        sequence: u64,
        recorded_at: u64,
        event: &AuditEvent,
        previous: &Fingerprint,
    ) -> Fingerprint {
        let mut input = Vec::with_capacity(128);
        input.extend_from_slice(AUDIT_DOMAIN);
        input.extend_from_slice(&sequence.to_be_bytes());
        input.extend_from_slice(&recorded_at.to_be_bytes());
        input.extend_from_slice(previous.as_bytes());
        // The event is hashed through its canonical JSON: it is a closed enum
        // with named fields, so `serde_json` produces one representation per
        // value, and a variant added later cannot collide with an older one.
        let encoded = serde_json::to_vec(event).unwrap_or_default();
        input.extend_from_slice(&(encoded.len() as u32).to_be_bytes());
        input.extend_from_slice(&encoded);
        Fingerprint::of(&input)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuditError {
    #[error("audit record {sequence} does not continue the chain")]
    Broken { sequence: u64 },
    #[error("audit record {sequence} is out of order")]
    OutOfOrder { sequence: u64 },
    #[error("audit chain ends on a different head than the one recorded: this is a fork")]
    Forked,
    /// The witness is genuine but predates a decision that widened the
    /// authority. Refused like a fork, and named apart from one so the
    /// operator is told to record a head rather than to hunt for a restore
    /// that never happened.
    #[error(
        "the recorded audit witness predates the authority decision at sequence {sequence}: \
         record the current head before restarting"
    )]
    WitnessOutdated { sequence: u64 },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chain() -> AuditChain {
        let mut chain = AuditChain::default();
        chain.append(AuditEvent::DomainBootstrapped, 1_000);
        chain.append(AuditEvent::IssuerInstalled { issuer_epoch: 1 }, 1_100);
        chain.append(
            AuditEvent::ClientGrantReleased {
                peer: "workstation".into(),
                generation: 5,
            },
            1_200,
        );
        chain
    }

    #[test]
    fn a_chain_verifies_against_itself_and_against_its_recorded_head() {
        let chain = chain();
        chain.verify(None).expect("intact chain");
        chain.verify(Some(&chain.head())).expect("known head");
    }

    /// The point of the chain: an edited record no longer hashes.
    #[test]
    fn an_edited_record_breaks_the_chain_at_its_own_index() {
        let mut chain = chain();
        chain.records[1].event = AuditEvent::IssuerRevoked { issuer_epoch: 1 };
        assert!(matches!(
            chain.verify(None),
            Err(AuditError::Broken { sequence: 1 })
        ));
    }

    /// A truncated chain is internally consistent — and that is exactly why the
    /// recorded head matters.
    #[test]
    fn a_truncated_chain_is_only_caught_by_the_recorded_head() {
        let full = chain();
        let head = full.head();
        let mut truncated = full;
        truncated.records.pop();

        truncated.verify(None).expect("internally consistent");
        assert!(matches!(
            truncated.verify(Some(&head)),
            Err(AuditError::Forked)
        ));
    }

    #[test]
    fn a_status_only_suffix_can_be_recovered_after_a_restart() {
        let mut chain = chain();
        let witness = chain.head();
        chain.append(
            AuditEvent::StatusPublished {
                target: "workstation".into(),
                status_epoch: 1,
            },
            1_300,
        );
        let growth = chain
            .verify_from_witness(&witness)
            .expect("read-only status suffix");
        assert_eq!(growth.appended, 1);
    }

    /// The lifecycle a client drives on its own is what the amendment of §8.1.2
    /// made unattended. Refusing to start over it would mean an operator has to
    /// be present for every renewal, which is the thing that was removed.
    #[test]
    fn unattended_client_lifecycle_after_the_witness_still_starts() {
        let mut chain = chain();
        let witness = chain.head();
        chain.append(
            AuditEvent::PeerAdmitted {
                peer: "workstation".into(),
                generation: 1,
            },
            1_300,
        );
        chain.append(
            AuditEvent::ExpiredRecoveryApproved {
                peer: "workstation".into(),
                generation: 2,
            },
            1_400,
        );
        chain.append(
            AuditEvent::PeerGenerationAdopted {
                peer: "workstation".into(),
                generation: 2,
            },
            1_500,
        );
        let growth = chain
            .verify_from_witness(&witness)
            .expect("per-peer lifecycle widens nothing");
        assert_eq!(growth.appended, 3);
        assert_eq!(growth.witnessed_sequence, 2);
    }

    /// The other half, and the reason the suffix is judged rather than
    /// accepted: a delegation installed after the witness is exactly what a
    /// restore could resurrect, and an operator was there when it happened.
    #[test]
    fn a_decision_after_the_witness_is_refused_and_named_as_such() {
        let mut chain = chain();
        let witness = chain.head();
        chain.append(AuditEvent::IssuerInstalled { issuer_epoch: 2 }, 1_300);
        assert!(matches!(
            chain.verify_from_witness(&witness),
            Err(AuditError::WitnessOutdated { sequence: 3 })
        ));
    }

    /// A witness that is nowhere in the chain is the case the witness exists
    /// for, and it stays a fork.
    #[test]
    fn a_witness_absent_from_the_chain_is_a_fork() {
        let chain = chain();
        assert!(matches!(
            chain.verify_from_witness(&Fingerprint::from_bytes([7; 32])),
            Err(AuditError::Forked)
        ));
    }

    #[test]
    fn an_empty_chain_has_the_zero_head() {
        let chain = AuditChain::default();
        assert_eq!(chain.head(), Fingerprint::from_bytes([0; 32]));
        chain
            .verify(Some(&Fingerprint::from_bytes([0; 32])))
            .expect("empty");
    }
}
