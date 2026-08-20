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
    StatusPublished {
        target: String,
        status_epoch: u64,
    },
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
    fn an_empty_chain_has_the_zero_head() {
        let chain = AuditChain::default();
        assert_eq!(chain.head(), Fingerprint::from_bytes([0; 32]));
        chain
            .verify(Some(&Fingerprint::from_bytes([0; 32])))
            .expect("empty");
    }
}
