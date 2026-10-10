//! Test-only plaintext fixtures for migration from retired profiles.toml.
//! This module is absent from shipped binaries; runtime profiles never serialize.

use anyhow::{Context, Result};
use serde::Serialize;

use super::{ClientConfig, ClientProfile, KeyNegotiationSettings, ProfileKind};

#[derive(Serialize)]
pub(crate) struct LegacyProfile<'a> {
    name: &'a str,
    endpoint: &'a str,
    private_key: &'a str,
    peer_public_key: &'a str,
    preshared_key: Option<&'a str>,
    address: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    address_v6: Option<&'a str>,
    allowed_ips: &'a str,
    persistent_keepalive: u16,
    heliosd_url: Option<&'a str>,
    ssh_target: Option<&'a str>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    profile_type: Option<ProfileKind>,
    key_negotiation: Option<&'a KeyNegotiationSettings>,
}

impl ClientProfile {
    pub(crate) fn legacy_fixture(&self) -> LegacyProfile<'_> {
        LegacyProfile {
            name: &self.name,
            endpoint: &self.endpoint,
            private_key: self.private_key.expose(),
            peer_public_key: &self.peer_public_key,
            preshared_key: self
                .preshared_key
                .as_ref()
                .map(aether::SecretString::expose),
            address: self.address.as_deref(),
            address_v6: self.address_v6.as_deref(),
            allowed_ips: &self.allowed_ips,
            persistent_keepalive: self.persistent_keepalive,
            heliosd_url: self.heliosd_url.as_deref(),
            ssh_target: self.ssh_target.as_deref(),
            profile_type: self.profile_type,
            key_negotiation: self.key_negotiation.as_ref(),
        }
    }
}

impl ClientConfig {
    pub(crate) fn encode_legacy_fixture(&self) -> Result<String> {
        #[derive(Serialize)]
        struct LegacyConfig<'a> {
            profiles: Vec<LegacyProfile<'a>>,
            selected: Option<&'a str>,
        }
        toml::to_string_pretty(&LegacyConfig {
            profiles: self
                .profiles
                .iter()
                .map(ClientProfile::legacy_fixture)
                .collect(),
            selected: self.selected.as_deref(),
        })
        .context("encoding the retired plaintext format for a migration test")
    }
}
