//! The authority gestures, with no terminal in them.
//!
//! Each one is the exact sequence the corresponding command performs, minus
//! the prompts and the printing. They live here rather than in `main.rs`
//! because the order of the steps is the interesting part — and because a
//! sequence that only exists inside an interactive program is a sequence
//! nothing exercises.
//!
//! # Why enrolling takes two objects
//!
//! [`open_with_authorized_key`] and [`add_key`] are separate on purpose: they
//! run against two different authenticators, plugged one at a time. The vault
//! enforces the rule — wrapping the master key for a new credential requires
//! the master key — and this split is what lets a caller obtain the two
//! secrets in the only order that is physically possible.
//!
//! Nothing here distinguishes the second key from the fifth. Registering
//! another one later is the same gesture with the same arguments, which is the
//! whole point: an operator who buys a third key runs `enrol` again.

use crate::vault::{
    draw_salt, AuthoritySecrets, AuthorityVault, SlotEnrolment, SlotRole, VaultError,
};
use aether::certificates::encoding::{generate_ml_dsa_87_keypair, MlDsa87PublicKey, TrustDomainId};
use base64::Engine as _;

use crate::authenticator::{Authenticator, AuthenticatorError, CredentialSubject, Opened};

/// Enforces the credential policy attached to a lifecycle scope.
///
/// Bootstrap has no online campaign to carry this field, so the offline
/// ceremony calls the same policy directly. Distinct credential identifiers
/// are mandatory: presenting one key twice never becomes two approvals.
pub fn require_scope_credentials(
    scope: aether::certificates::status::CampaignScope,
    openings: &[&Opened],
) -> Result<()> {
    let required = usize::from(scope.required_credentials());
    if openings.len() != required {
        return Err(GestureError::Anchors(format!(
            "la portée {scope:?} exige {required} credentials actifs distincts"
        )));
    }
    require_distinct_credentials(required, openings)
}

/// Exactly `required` openings, each from a different credential.
///
/// The rule behind [`require_scope_credentials`], for the gestures that run
/// outside any campaign — enrollment among them (ADR-008 §4).
pub fn require_distinct_credentials(required: usize, openings: &[&Opened]) -> Result<()> {
    if openings.len() != required {
        return Err(GestureError::Anchors(format!(
            "ce geste exige {required} credential(s) actif(s) distinct(s)"
        )));
    }
    for (index, opening) in openings.iter().enumerate() {
        if openings[..index]
            .iter()
            .any(|earlier| earlier.credential_id == opening.credential_id)
        {
            return Err(GestureError::Anchors(
                "le même credential a été présenté deux fois".into(),
            ));
        }
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum GestureError {
    #[error(transparent)]
    Vault(#[from] VaultError),
    #[error(transparent)]
    Authenticator(#[from] AuthenticatorError),
    #[error("objet de cycle de vie refusé : {0}")]
    Certificate(#[from] aether::certificates::CertificateError),
    #[error("génération des ancres d'autorité : {0}")]
    Anchors(String),
}

pub type Result<T> = std::result::Result<T, GestureError>;

/// What `init` is asked for.
pub struct NewAuthority {
    pub rp_id: String,
    pub trust_domain_id: TrustDomainId,
    pub label: String,
    pub role: SlotRole,
}

/// What `enrol` is asked for. Identical whether it is the second key or the
/// eighth.
pub struct NewKey {
    pub label: String,
    pub role: SlotRole,
}

pub struct Created {
    pub vault: AuthorityVault,
    /// The half of the anchor that leaves this program: what `astra bootstrap`
    /// is given, and the only `CA-PQ` value anything else ever sees.
    pub ca_pq_public_key: MlDsa87PublicKey,
    /// What the first key released while the vault was being created.
    ///
    /// Handed back so a ceremony that goes on to register the second key can
    /// open the vault with it, rather than asking the same key for a second
    /// press. Secret: never logged, serialized nor shown.
    pub opening: Opened,
}

/// A key just registered, and what it released while registering.
///
/// The new key's opening is a valid opening of the vault it now belongs to: a
/// ceremony that has to try that key afterwards uses it instead of asking for
/// another press. Secret, like every [`Opened`].
pub struct AddedKey {
    pub slot_id: [u8; 16],
    pub opening: Opened,
}

/// Creates the vault around fresh anchors and registers the first key.
///
/// The anchors are generated **before** the token is asked for anything: an
/// operator who has to unplug and retry should not be doing it around a
/// half-made authority.
pub fn create_authority(
    key: &dyn Authenticator,
    request: &NewAuthority,
    pin: &str,
    now_unix: u64,
) -> Result<Created> {
    let (ca_pq_private_key, ca_pq_public_key) =
        generate_ml_dsa_87_keypair().map_err(|error| GestureError::Anchors(error.to_string()))?;
    let ca_tls_key =
        rcgen::KeyPair::generate().map_err(|error| GestureError::Anchors(error.to_string()))?;
    let secrets = AuthoritySecrets {
        ca_pq_private_key: encode(&ca_pq_private_key),
        ca_pq_public_key: ca_pq_public_key.to_base64(),
        ca_tls_private_key: encode(&ca_tls_key.serialize_der()),
        retained_ca_tls: None,
    };

    let registration =
        key.register(&request.rp_id, &subject(&request.trust_domain_id), &[], pin)?;
    // The salt has to exist before the vault does: the first slot's secret is
    // this token's `hmac-secret` output *for this salt*.
    let salt = draw_salt()?;
    let opened = key.derive(
        &request.rp_id,
        std::slice::from_ref(&registration.credential_id),
        &salt,
        pin,
    )?;

    let vault = AuthorityVault::create(
        request.trust_domain_id,
        &request.rp_id,
        salt,
        &secrets,
        SlotEnrolment {
            role: request.role,
            label: request.label.clone(),
            credential_id: registration.credential_id,
            credential_public_key: registration.credential_public_key,
            aaguid: registration.aaguid,
            enrolled_at: now_unix,
        },
        &opened.secret,
        now_unix,
    )?;
    Ok(Created {
        vault,
        ca_pq_public_key,
        opening: opened,
    })
}

/// Resolves the connected token against the vault's slots, and derives its
/// secret.
///
/// One assertion answers both questions: the allow-list carries every
/// registered credential, and the token names the one it holds.
pub fn open_with_authorized_key(
    key: &dyn Authenticator,
    vault: &AuthorityVault,
    pin: &str,
) -> Result<Opened> {
    let opened = key.derive(&vault.rp_id, &vault.credential_ids()?, &vault.salt()?, pin)?;
    // Resolves the slot here so a caller cannot proceed with a credential the
    // vault does not know — the error would otherwise surface two steps later,
    // after the operator has swapped tokens.
    vault.slot_for_credential(&opened.credential_id)?;
    Ok(opened)
}

/// Opens the vault with one named credential, and with no other.
///
/// For the ceremony that has just obtained an approval from `credential_id`
/// and must open the vault with that same key. The allow-list carries that
/// identifier alone, so another token presented in its place holds nothing it
/// may answer for; and a token that answered anyway, for a credential it was
/// not offered, is refused here rather than trusted.
pub fn open_with_credential(
    key: &dyn Authenticator,
    vault: &AuthorityVault,
    credential_id: &[u8],
    pin: &str,
) -> Result<Opened> {
    // A credential this vault does not hold is refused before the press.
    vault.slot_for_credential(credential_id)?;
    let opened = key.derive(&vault.rp_id, &[credential_id.to_vec()], &vault.salt()?, pin)?;
    if opened.credential_id != credential_id {
        return Err(GestureError::Anchors(
            "la clé qui ouvre le coffre n'est pas celle qui vient d'approuver ; recommencer avec \
             une seule clé branchée"
                .into(),
        ));
    }
    vault.slot_for_credential(&opened.credential_id)?;
    Ok(opened)
}

/// Registers another security key, using a secret an authorized one released.
///
/// `new` is a **different** device from the one that produced `opening`. The
/// exclusion list is every credential already registered, so a token that
/// already holds a slot of this vault refuses rather than taking a second: two
/// slots on one object is not a recovery, though it reads as one.
pub fn add_key(
    new: &dyn Authenticator,
    vault: &mut AuthorityVault,
    opening: &Opened,
    request: &NewKey,
    pin: &str,
    now_unix: u64,
) -> Result<[u8; 16]> {
    add_key_opened(new, vault, opening, request, pin, now_unix).map(|added| added.slot_id)
}

/// [`add_key`], keeping what the new key released.
///
/// The same single assertion on the new key: its derivation is what wraps the
/// master key for it, and it is handed back rather than dropped.
pub fn add_key_opened(
    new: &dyn Authenticator,
    vault: &mut AuthorityVault,
    opening: &Opened,
    request: &NewKey,
    pin: &str,
    now_unix: u64,
) -> Result<AddedKey> {
    let known = vault.credential_ids()?;
    let salt = vault.salt()?;
    let registration = new.register(&vault.rp_id, &subject(&vault.trust_domain_id), &known, pin)?;
    let new_secret = new.derive(
        &vault.rp_id,
        std::slice::from_ref(&registration.credential_id),
        &salt,
        pin,
    )?;
    let slot_id = vault.add_slot(
        &opening.credential_id,
        &opening.secret,
        SlotEnrolment {
            role: request.role,
            label: request.label.clone(),
            credential_id: registration.credential_id,
            credential_public_key: registration.credential_public_key,
            aaguid: registration.aaguid,
            enrolled_at: now_unix,
        },
        &new_secret.secret,
    )?;
    Ok(AddedKey {
        slot_id,
        opening: new_secret,
    })
}

/// Withdraws a key, re-sealing the body under the table it leaves behind.
pub fn remove_key(vault: &mut AuthorityVault, opening: &Opened, slot_id: &[u8; 16]) -> Result<()> {
    vault.remove_slot(&opening.credential_id, &opening.secret, slot_id)?;
    Ok(())
}

/// Proves a token opens the anchors, not merely a slot.
///
/// ADR-008 §4 finalises the bootstrap only «après enregistrement et essai des
/// deux clés», and a slot that unwraps a master key which no longer opens the
/// body is exactly what that trial has to catch. Only reading the payload
/// finds it, so this reads it — and drops it immediately.
pub fn prove_anchors_open(vault: &AuthorityVault, opening: &Opened) -> Result<()> {
    let secrets = vault.open(&opening.credential_id, &opening.secret)?;
    let readable = !secrets.ca_pq_private_key.is_empty() && !secrets.ca_tls_private_key.is_empty();
    drop(secrets);
    if !readable {
        return Err(GestureError::Anchors(
            "le corps du coffre s'est ouvert sur des ancres vides".into(),
        ));
    }
    Ok(())
}

/// Ties a credential to one trust domain, so a key registered for two
/// authorities shows two entries rather than one ambiguous one.
fn subject(trust_domain_id: &TrustDomainId) -> CredentialSubject {
    CredentialSubject {
        user_id: trust_domain_id.as_bytes().to_vec(),
        user_name: format!("astra-{trust_domain_id}"),
        display_name: "Autorité Helios".to_string(),
    }
}

fn encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::SlotSecret;
    use aether::certificates::status::CampaignScope;

    fn opened(id: u8) -> Opened {
        Opened {
            credential_id: vec![id],
            secret: SlotSecret::new(vec![id; 32]),
        }
    }

    #[test]
    fn bootstrap_requires_two_distinct_credentials() {
        let first = opened(1);
        let second = opened(2);
        require_scope_credentials(CampaignScope::GatewayBootstrap, &[&first, &second])
            .expect("two credentials");
        assert!(require_scope_credentials(CampaignScope::GatewayBootstrap, &[&first]).is_err());
        assert!(
            require_scope_credentials(CampaignScope::GatewayBootstrap, &[&first, &first]).is_err()
        );
    }
}
