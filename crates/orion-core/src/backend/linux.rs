//! Backend Linux : pilote strongSwan via `swanctl` (cible uniquement).
//!
//! Compilé derrière la feature `linux-strongswan`. Nécessite un charon en cours
//! d'exécution, le binaire `swanctl`, et des privilèges root (config VPN). Ne
//! compile/valide que sur la cible — jamais sur WSL2.
//!
//! Flux : on génère un fragment de configuration swanctl pour la connexion
//! `orion`, on le charge (`swanctl --load-all`), puis on initie la SA
//! (`swanctl --initiate`). L'état est déduit du code de retour.

use async_trait::async_trait;
use aether::TunnelState;
use tokio::process::Command;

use crate::config::{AuthConfig, ClientProfile};
use crate::events::ClientEvent;

use super::{EventSink, VpnBackend};

const CONN_NAME: &str = "orion";
const CONF_PATH: &str = "/etc/swanctl/conf.d/orion.conf";

pub struct StrongSwanBackend;

impl StrongSwanBackend {
    pub fn new() -> Self {
        Self
    }

    /// Construit le fragment swanctl pour ce profil.
    fn render_conf(profile: &ClientProfile) -> anyhow::Result<String> {
        let (ike, esp) = profile.resolved_proposals();
        let local_id = profile.local_id.clone().unwrap_or_default();
        let remote_id = profile.remote_id.clone().unwrap_or_else(|| "%any".to_string());

        // L'authentification détaillée (secrets/certs) doit être déposée dans la
        // section `secrets` de swanctl ; ici on ne décrit que la topologie.
        let local_auth = match &profile.auth {
            AuthConfig::Psk { .. } => "psk",
            AuthConfig::Cert { .. } => "pubkey",
            AuthConfig::Eap { .. } => "eap-mschapv2",
        };

        Ok(format!(
            r#"connections {{
    {CONN_NAME} {{
        version = 2
        remote_addrs = {gw}
        local_addrs = %any
        proposals = {ike}
        mobike = yes
        local {{
            auth = {local_auth}
            id = {local_id}
        }}
        remote {{
            auth = pubkey
            id = {remote_id}
        }}
        children {{
            {CONN_NAME} {{
                esp_proposals = {esp}
                start_action = none
            }}
        }}
    }}
}}
"#,
            gw = profile.gateway,
        ))
    }

    async fn run(args: &[&str]) -> anyhow::Result<()> {
        let status = Command::new("swanctl").args(args).status().await?;
        if !status.success() {
            anyhow::bail!("swanctl {:?} a échoué ({status})", args);
        }
        Ok(())
    }
}

impl Default for StrongSwanBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl VpnBackend for StrongSwanBackend {
    async fn connect(&self, profile: &ClientProfile, sink: &EventSink) -> anyhow::Result<()> {
        sink(ClientEvent::state(TunnelState::Connecting));
        sink(ClientEvent::log(
            "info",
            format!("strongSwan : négociation IKEv2 vers {}", profile.gateway),
        ));

        let conf = Self::render_conf(profile)?;
        tokio::fs::write(CONF_PATH, conf).await?;
        // TODO(cible) : écrire les secrets (PSK/EAP) ou installer le certificat
        // dans la section `secrets` avant le load — gestion sécurisée à durcir.
        Self::run(&["--load-all"]).await?;
        Self::run(&["--initiate", "--child", CONN_NAME]).await?;

        sink(ClientEvent::state(TunnelState::Up));
        sink(ClientEvent::log("info", "strongSwan : CHILD_SA établie"));
        Ok(())
    }

    async fn disconnect(&self, sink: &EventSink) -> anyhow::Result<()> {
        sink(ClientEvent::log("info", "strongSwan : fermeture de la SA"));
        let _ = Self::run(&["--terminate", "--ike", CONN_NAME]).await;
        sink(ClientEvent::state(TunnelState::Down));
        Ok(())
    }

    fn kind(&self) -> &'static str {
        "linux-strongswan"
    }
}
