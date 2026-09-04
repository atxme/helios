//! Where an operator campaign is fetched from, and where the assertion goes.
//!
//! Amendment of 4 September 2026, spec §8.5. Three transports, one gesture:
//!
//! * **Tunnel** — `--heliosd-url` and `--operation-id`, the priority path.
//! * **HTTPS** — `--authority-url` and `--operation-id`, for an operator who
//!   really has no tunnel.
//! * **Offline** — `--request`/`--campaign` and `--out`, last resort, and not
//!   this module: it reads and writes files rather than dialling anything.
//!
//! # Why there is no fallback
//!
//! A transport that fails is an error, never a silent retry on the other one.
//! A fallback would make the path a ceremony actually took depend on a
//! transient failure, and the operator would believe they had approved inside
//! the tunnel something that left by the public origin. Choosing is the
//! operator's; recovering from a wrong choice is re-running the command.
//!
//! # What the transport is not allowed to decide
//!
//! Nothing. Both arms verify through the same [`origin::Origin::accept`]:
//! the objects carry the signatures, so what arrives through a tunnel is
//! trusted exactly as much — and exactly as little — as what arrives over
//! HTTPS. In particular the relying party a channel reports is displayed and
//! compared, never adopted.

use aether::certificates::encoding::Id16;
use aether::certificates::status::AstraSignerResult;
use anyhow::{bail, Result};

use crate::{origin, tunnel};

/// One campaign, over the transport the operator chose.
pub enum Campaign {
    /// Astra's public origin (§8.2).
    Origin(origin::Origin),
    /// The operator's own gateway, over the typed in-tunnel routes (§8.5).
    Tunnel(tunnel::Tunnel),
}

impl Campaign {
    /// Resolves the operator's choice, or says what is missing.
    ///
    /// Named here rather than left to clap: the two options are legal
    /// individually and meaningless together, and a caller that supplied
    /// neither must be told which pair to complete — not have a default
    /// picked for it.
    pub fn select(authority_url: Option<&str>, heliosd_url: Option<&str>) -> Result<Self> {
        match (authority_url, heliosd_url) {
            (Some(url), None) => Ok(Self::Origin(origin::Origin::new(url)?)),
            (None, Some(url)) => Ok(Self::Tunnel(tunnel::Tunnel::new(url)?)),
            (Some(_), Some(_)) => bail!(
                "choisir un seul transport : --heliosd-url pour le tunnel, --authority-url pour \
                 l'origine publique. Les deux ensemble ne veulent rien dire, et il n'y a pas de \
                 repli de l'un vers l'autre."
            ),
            (None, None) => bail!(
                "aucun transport : --heliosd-url si le tunnel est monté, sinon --authority-url. \
                 Sans tunnel ni origine joignable, employer le mode hors ligne de cette commande."
            ),
        }
    }

    /// How this campaign is being carried, for the line the operator reads.
    pub fn description(&self) -> &'static str {
        match self {
            Self::Origin(_) => "origine publique Astra (§8.2)",
            Self::Tunnel(_) => "tunnel WireGuard, routes opérateur de la gateway (§8.5)",
        }
    }

    /// Reads the operation and the campaign it is waiting on.
    pub fn fetch(&self, operation_id: &Id16) -> Result<origin::CampaignRequest> {
        match self {
            Self::Origin(origin) => origin.fetch(operation_id),
            Self::Tunnel(tunnel) => tunnel.fetch_campaign(operation_id),
        }
    }

    /// Downloads the encrypted vault this campaign names, still encrypted.
    pub fn encrypted_vault(
        &self,
        request: &origin::CampaignRequest,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        match self {
            Self::Origin(origin) => origin.encrypted_vault(request),
            Self::Tunnel(tunnel) => tunnel.campaign_vault(request),
        }
    }

    /// Posts the operator's approval, and reports where the operation landed.
    pub fn submit(
        &self,
        operation_id: &Id16,
        result_token: &str,
        result: &AstraSignerResult,
    ) -> Result<astra::signing::SigningOperationState> {
        match self {
            Self::Origin(origin) => origin.submit(operation_id, result_token, result),
            Self::Tunnel(tunnel) => tunnel.submit_campaign(operation_id, result_token, result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Choosing is the operator's, and there is no default.
    ///
    /// The two flags are legal apart and meaningless together. Neither one is
    /// a failure the other recovers from: a campaign that silently left by the
    /// public origin after the tunnel refused it is a ceremony the operator
    /// believes happened somewhere it did not.
    #[test]
    fn a_transport_is_chosen_explicitly_and_never_defaulted() {
        assert!(
            Campaign::select(None, None).is_err(),
            "no transport is a refusal, not a default"
        );
        assert!(
            Campaign::select(
                Some("https://astra.example"),
                Some("http://100.64.0.1:8080")
            )
            .is_err(),
            "two transports name two paths, and the ceremony takes one"
        );
        assert!(matches!(
            Campaign::select(Some("https://astra.example"), None),
            Ok(Campaign::Origin(_))
        ));
        assert!(matches!(
            Campaign::select(None, Some("http://100.64.0.1:8080")),
            Ok(Campaign::Tunnel(_))
        ));
    }

    /// The public origin stays HTTPS-only; the tunnel does not need TLS.
    ///
    /// `http://` towards the gateway is not a weakening: the address only
    /// exists inside an encrypted, mutually authenticated WireGuard tunnel.
    /// Towards Astra's public origin it would be, and is refused.
    #[test]
    fn the_public_origin_refuses_plain_http_and_the_tunnel_does_not() {
        assert!(Campaign::select(Some("http://astra.example"), None).is_err());
        assert!(Campaign::select(None, Some("http://100.64.0.1:8080")).is_ok());
    }
}
