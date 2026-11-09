//! The delegation this authority issues under, and the policy it is bound by.
//!
//! The only writer of `issuer` and `astra_policy_fingerprint`, and it writes
//! them together: a pin persisted without its delegation would widen what the
//! authority may do unattended before anything authorized it, and a delegation
//! persisted without its pin would be refused on the next read by the policy it
//! was meant to install.

use super::{AstraIssuerState, AstraPolicyPin, AstraRegistry, AuditEvent, RegistryError};

impl AstraRegistry {
    /// Installs the delegation the operator companion signed (spec §9.5).
    ///
    /// The epoch must move forward. A delegation reinstalled at an epoch
    /// already used would let a withdrawn intermediate come back under a
    /// signature that is still perfectly valid — the same walk-back the
    /// credential document refuses, and for the same reason.
    pub fn install_issuer(
        &mut self,
        issuer: AstraIssuerState,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        self.install_issuer_adopting_policy(issuer, None, now_unix)
    }

    /// Installs a delegation and, in the same durable write, the issuance
    /// policy it carried the domain onto.
    ///
    /// One write rather than two: a pin persisted without its delegation
    /// would widen what the authority may do unattended before anything
    /// authorized it, and a delegation persisted without its pin would be
    /// refused on the next read by the policy it was meant to install.
    pub fn install_issuer_adopting_policy(
        &mut self,
        issuer: AstraIssuerState,
        adopted_policy: Option<AstraPolicyPin>,
        now_unix: u64,
    ) -> Result<(), RegistryError> {
        // Installing the delegation already held is a no-op, not a walk-back: a
        // companion whose response was lost retries the same bytes, and §8.2 makes
        // that replay the repair. Only a *different* delegation at a spent epoch is
        // the substitution this refuses.
        let already_held = self.state.issuer.as_ref() == Some(&issuer);
        if let Some(installed) = self.state.issuer.as_ref().filter(|_| !already_held) {
            if issuer.issuer_epoch <= installed.issuer_epoch {
                return Err(RegistryError::IssuerEpochNotAdvancing {
                    installed: installed.issuer_epoch,
                    offered: issuer.issuer_epoch,
                });
            }
        }
        // After the refusal and not before it: a pin left in memory would be persisted
        // by the next unrelated save, without its delegation.
        if let Some(policy) = adopted_policy {
            self.state.astra_policy_fingerprint = policy;
            self.state.audit.append(
                AuditEvent::IssuancePolicyAdopted {
                    policy_fingerprint: policy.fingerprint().to_string(),
                },
                now_unix,
            );
        }
        if already_held {
            // The pin may still have moved just above, so the write is not skipped
            // with the install.
            return if adopted_policy.is_some() {
                self.save()
            } else {
                Ok(())
            };
        }
        let issuer_epoch = issuer.issuer_epoch;
        self.state.issuer = Some(issuer);
        self.state
            .audit
            .append(AuditEvent::IssuerInstalled { issuer_epoch }, now_unix);
        self.save()
    }
}
