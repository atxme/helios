//! Client VPN profile: editable in the UI, persisted locally in TOML.
//!
//! **WireGuard** model (ADR-001): a peer is identified by its Curve25519
//! public key and reached via a UDP endpoint. There's no CA, no EAP, no
//! cryptographic proposal to choose — WireGuard only has one suite.
//!
//! Post-quantum protection goes through the `PresharedKey` slot, but it is
//! **not** stored in this file: the PQC PSK is negotiated with ML-KEM-768 on
//! each connection and is never persisted. What the profile can carry is a
//! *static* PSK entered by hand, which disables this negotiation.
//!
//! The `private_key` / `preshared_key` fields are **secrets**: `Debug` is
//! masked so they don't leak into logs.

use std::fmt;
use std::path::PathBuf;

use aether::key_negotiation::ProtectionMode;
use anyhow::{Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Default `AllowedIPs`: all traffic goes through the tunnel.
///
/// It's this `0.0.0.0/0`, combined with the adapter lifecycle invariant
/// (see [`crate::backend`]), that makes WireGuard **drop** packets instead of
/// letting them leak in clear when the session is dead.
pub const DEFAULT_ALLOWED_IPS: &str = "0.0.0.0/0";

/// Enforced keepalive: without traffic, WireGuard doesn't handshake and our
/// state inference would wrongly conclude the tunnel is down (ADR-001 §3).
pub const DEFAULT_KEEPALIVE_SECS: u16 = 25;

/// Public settings for the pre-WireGuard key-negotiation service.
///
/// The client certificate and its private key stay in a protected identity
/// store selected by the Orion shell. Only an opaque identity name and the
/// public gateway CA are persisted in the VPN profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyNegotiationSettings {
    pub mode: ProtectionMode,
    /// Persistent local security floor. Helios enforces its own copy, so a
    /// network attacker cannot lower both sides through negotiation.
    #[serde(default)]
    pub minimum_mode: ProtectionMode,
    /// Public UDP endpoint, normally the WireGuard host on port 51821.
    pub endpoint: String,
    /// DNS name authenticated by the gateway certificate.
    pub server_name: String,
    /// DER gateway CA certificate encoded as base64.
    pub gateway_ca_der: String,
    /// Base64-encoded JSON ML-DSA-65 gateway certificate.
    pub gateway_pq_certificate: String,
    /// Opaque lookup name in the shell's protected identity store.
    pub identity: String,
}

/// A complete VPN profile, as edited by the user in the UI.
#[derive(Clone, Serialize, Deserialize)]
pub struct ClientProfile {
    /// Unique friendly name (selection key in the list).
    pub name: String,
    /// Gateway's UDP endpoint: `IP:port` or `FQDN:port`. **Not** an HTTP URL.
    pub endpoint: String,
    /// Client's Curve25519 private key (base64). **Secret.**
    #[serde(default)]
    pub private_key: String,
    /// Gateway's Curve25519 public key (base64) — the peer's identity.
    #[serde(default)]
    pub peer_public_key: String,
    /// **Static** PSK shared out of band (base64). **Secret.**
    ///
    /// If set, it is sovereign: the core no longer negotiates anything and
    /// sets this secret as is. The PQC PSK from the ML-KEM exchange never
    /// lands here — it isn't persisted, it's renegotiated on each connection.
    /// `None` is therefore the *normal* case for a Helios profile, not a gap.
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// Virtual address assigned by the gateway (CGNAT, e.g. `100.64.1.2/32`).
    /// Derived on the gateway side by `helios-provisioning`, received on enrollment.
    #[serde(default)]
    pub address: Option<String>,
    /// Traffic routed into the tunnel. Defaults to [`DEFAULT_ALLOWED_IPS`].
    #[serde(default = "default_allowed_ips")]
    pub allowed_ips: String,
    /// Keepalive in seconds. Defaults to [`DEFAULT_KEEPALIVE_SECS`].
    #[serde(default = "default_keepalive")]
    pub persistent_keepalive: u16,
    /// Internal heliosd API URL, reachable **only once the tunnel is
    /// mounted** (e.g. `http://100.64.0.1:8080`). `None` = no enriched telemetry.
    #[serde(default)]
    pub heliosd_url: Option<String>,
    /// Authenticated public negotiation performed before WireGuard is mounted.
    #[serde(default)]
    pub key_negotiation: Option<KeyNegotiationSettings>,
}

fn default_allowed_ips() -> String {
    DEFAULT_ALLOWED_IPS.to_string()
}

fn default_keepalive() -> u16 {
    DEFAULT_KEEPALIVE_SECS
}

/// Masked `Debug`: never let the private key or PSK leak into logs.
impl fmt::Debug for ClientProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientProfile")
            .field("name", &self.name)
            .field("endpoint", &self.endpoint)
            .field("private_key", &"***")
            .field("peer_public_key", &self.peer_public_key)
            .field("preshared_key", &self.preshared_key.as_ref().map(|_| "***"))
            .field("address", &self.address)
            .field("allowed_ips", &self.allowed_ips)
            .field("persistent_keepalive", &self.persistent_keepalive)
            .field("heliosd_url", &self.heliosd_url)
            .field("key_negotiation", &self.key_negotiation)
            .finish()
    }
}

impl ClientProfile {
    /// Is the profile usable to mount a tunnel?
    ///
    /// An incomplete profile must not be presented as connectable: we fail
    /// **before** touching the network rather than mounting an adapter that
    /// will never handshake.
    pub fn validate(&self) -> Result<()> {
        if self.endpoint.trim().is_empty() {
            anyhow::bail!("l'endpoint de la gateway (IP/FQDN:port) est requis");
        }
        if self.private_key.trim().is_empty() {
            anyhow::bail!("la clé privée du client est requise (enrôlement non effectué ?)");
        }
        if self.peer_public_key.trim().is_empty() {
            anyhow::bail!("la clé publique de la gateway est requise");
        }
        if let Some(settings) = &self.key_negotiation {
            if settings.endpoint.trim().is_empty()
                || settings.server_name.trim().is_empty()
                || settings.gateway_ca_der.trim().is_empty()
                || settings.gateway_pq_certificate.trim().is_empty()
                || settings.identity.trim().is_empty()
            {
                anyhow::bail!("key-negotiation settings are incomplete");
            }
            if !settings.mode.satisfies(settings.minimum_mode) {
                anyhow::bail!("selected key-negotiation mode is below the profile security floor");
            }
            let gateway_pq_certificate: aether::key_negotiation::PqCertificate =
                serde_json::from_slice(
                    &base64::engine::general_purpose::STANDARD
                        .decode(settings.gateway_pq_certificate.trim())
                        .context("decoding the gateway PQ certificate")?,
                )
                .context("parsing the gateway PQ certificate")?;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("system clock predates the Unix epoch")?
                .as_secs();
            gateway_pq_certificate
                .verify_self_signed(
                    aether::key_negotiation::PqCertificateRole::Gateway,
                    Some(&settings.server_name),
                    &self.peer_public_key,
                    now,
                )
                .context("verifying the pinned gateway PQ certificate")?;
            match (settings.mode, self.has_preshared_key()) {
                (ProtectionMode::StaticPsk, false) => {
                    anyhow::bail!("static key-negotiation mode requires a profile PSK")
                }
                (ProtectionMode::Classic | ProtectionMode::MlKem, true) => {
                    anyhow::bail!("a profile PSK is only valid with static key-negotiation mode")
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Public key corresponding to the profile's private key.
    ///
    /// It's the only half of the pair meant to leave the machine: the user
    /// communicates it to the operator to be admitted on the gateway
    /// (ADR-004 §6). `None` if the profile has no private key yet, or if it
    /// is unreadable.
    pub fn public_key(&self) -> Option<String> {
        aether::wg::public_from_private(&self.private_key).ok()
    }

    /// Is the `PresharedKey` slot set in this profile?
    ///
    /// **Says nothing about the secret's origin**, and can't say anything: a
    /// PQC PSK derived from ML-KEM is never persisted, it only exists in the
    /// ephemeral profile the core passes to the backend when setting it. A
    /// `true` read from the *saved* profile therefore always denotes a static
    /// PSK. To distinguish the two in the UI, it's
    /// [`crate::events::PskKind`] that is authoritative, not this predicate.
    pub fn has_preshared_key(&self) -> bool {
        self.preshared_key
            .as_deref()
            .is_some_and(|k| !k.trim().is_empty())
    }
}

impl Default for ClientProfile {
    fn default() -> Self {
        Self {
            name: "nouveau".to_string(),
            endpoint: String::new(),
            private_key: String::new(),
            peer_public_key: String::new(),
            preshared_key: None,
            address: None,
            allowed_ips: default_allowed_ips(),
            persistent_keepalive: DEFAULT_KEEPALIVE_SECS,
            heliosd_url: None,
            key_negotiation: None,
        }
    }
}

/// Persisted client configuration: set of profiles + current selection.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClientConfig {
    #[serde(default)]
    pub profiles: Vec<ClientProfile>,
    /// Name of the currently selected profile.
    #[serde(default)]
    pub selected: Option<String>,
}

impl ClientConfig {
    /// Path to the config file. Overridden by `ORION_CONFIG` (tests/dev),
    /// otherwise the OS's standard config directory (`directories`).
    pub fn path() -> Result<PathBuf> {
        if let Ok(p) = std::env::var("ORION_CONFIG") {
            return Ok(PathBuf::from(p));
        }
        let dirs = directories::ProjectDirs::from("net", "helios", "orion")
            .context("impossible de déterminer le répertoire de config de l'OS")?;
        Ok(dirs.config_dir().join("profiles.toml"))
    }

    /// Loads the config from disk. Returns an empty config if the file
    /// doesn't exist yet (first launch).
    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read_to_string(&path) {
            Ok(raw) => {
                toml::from_str(&raw).with_context(|| format!("config invalide: {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("lecture de {}", path.display())),
        }
    }

    /// Persists the config atomically (temporary write + rename), same
    /// scheme as [`aether::NetworkConfig::save`].
    pub fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("création de {}", parent.display()))?;
        }
        let raw = toml::to_string_pretty(self).context("sérialisation TOML")?;
        let tmp = path.with_extension("toml.tmp");
        std::fs::write(&tmp, raw.as_bytes())
            .with_context(|| format!("écriture de {}", tmp.display()))?;
        std::fs::rename(&tmp, &path).context("rename atomique")?;
        Ok(())
    }

    /// Returns the profile with this name, if any.
    pub fn find(&self, name: &str) -> Option<&ClientProfile> {
        self.profiles.iter().find(|p| p.name == name)
    }

    /// Inserts or replaces a profile (key = `name`).
    pub fn upsert(&mut self, profile: ClientProfile) {
        match self.profiles.iter_mut().find(|p| p.name == profile.name) {
            Some(slot) => *slot = profile,
            None => self.profiles.push(profile),
        }
    }

    /// Removes the profile with this name. Deselects it if it was the current profile.
    pub fn remove(&mut self, name: &str) {
        self.profiles.retain(|p| p.name != name);
        if self.selected.as_deref() == Some(name) {
            self.selected = self.profiles.first().map(|p| p.name.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upsert_and_remove() {
        let mut cfg = ClientConfig::default();
        cfg.upsert(ClientProfile {
            name: "a".into(),
            ..ClientProfile::default()
        });
        cfg.upsert(ClientProfile {
            name: "b".into(),
            ..ClientProfile::default()
        });
        cfg.selected = Some("b".into());
        assert_eq!(cfg.profiles.len(), 2);

        // upsert on an existing name replaces, doesn't add.
        cfg.upsert(ClientProfile {
            name: "a".into(),
            endpoint: "203.0.113.1:51820".into(),
            ..ClientProfile::default()
        });
        assert_eq!(cfg.profiles.len(), 2);
        assert_eq!(cfg.find("a").unwrap().endpoint, "203.0.113.1:51820");

        cfg.remove("b");
        assert_eq!(cfg.profiles.len(), 1);
        assert_eq!(cfg.selected.as_deref(), Some("a")); // auto re-selection
    }

    #[test]
    fn disk_roundtrip() {
        let dir = std::env::temp_dir().join(format!("orion-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("profiles.toml");
        std::env::set_var("ORION_CONFIG", &path);

        let mut cfg = ClientConfig::default();
        cfg.upsert(ClientProfile {
            name: "site-a".into(),
            endpoint: "203.0.113.10:51820".into(),
            private_key: "cHJpdmF0ZQ==".into(),
            peer_public_key: "cHVibGlj".into(),
            preshared_key: Some("cHNr".into()),
            address: Some("100.64.1.2/32".into()),
            ..ClientProfile::default()
        });
        cfg.selected = Some("site-a".into());
        cfg.save().unwrap();

        let loaded = ClientConfig::load().unwrap();
        assert_eq!(loaded.profiles.len(), 1);
        let p = loaded.find("site-a").unwrap();
        assert_eq!(p.endpoint, "203.0.113.10:51820");
        assert_eq!(p.address.as_deref(), Some("100.64.1.2/32"));
        // WireGuard defaults must survive the round-trip.
        assert_eq!(p.allowed_ips, DEFAULT_ALLOWED_IPS);
        assert_eq!(p.persistent_keepalive, DEFAULT_KEEPALIVE_SECS);
        assert!(p.has_preshared_key());
        assert_eq!(loaded.selected.as_deref(), Some("site-a"));

        std::env::remove_var("ORION_CONFIG");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn secrets_masked_in_debug() {
        let p = ClientProfile {
            private_key: "TRES_SECRET".into(),
            preshared_key: Some("PSK_SECRET".into()),
            ..ClientProfile::default()
        };
        let dump = format!("{p:?}");
        assert!(
            !dump.contains("TRES_SECRET"),
            "the private key leaks into logs"
        );
        assert!(!dump.contains("PSK_SECRET"), "the PSK leaks into logs");
    }
}
