//! Explicit operator generation of the stable tunnel ULA prefix.

use aether::{net::TunnelPrefixV6, NetworkConfig};
use anyhow::Context;

#[derive(Debug, PartialEq, Eq)]
enum PrefixAction {
    Existing(TunnelPrefixV6),
    Generated(TunnelPrefixV6),
}

fn choose_prefix<E: std::fmt::Display>(
    network: &mut NetworkConfig,
    fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> anyhow::Result<PrefixAction> {
    if let Some(prefix) = network.wg_address_v6 {
        return Ok(PrefixAction::Existing(prefix));
    }

    let mut global_id = [0u8; 5];
    fill(&mut global_id)
        .map_err(|error| anyhow::anyhow!("generating IPv6 ULA Global ID: {error}"))?;
    let prefix = TunnelPrefixV6::from_global_id(global_id);
    network.wg_address_v6 = Some(prefix);
    Ok(PrefixAction::Generated(prefix))
}

fn persist_prefix<E: std::fmt::Display>(
    fill: impl FnOnce(&mut [u8]) -> Result<(), E>,
) -> anyhow::Result<PrefixAction> {
    let mut network = NetworkConfig::load().context("loading the network config")?;
    let action = choose_prefix(&mut network, fill)?;
    if matches!(action, PrefixAction::Generated(_)) {
        network
            .save()
            .context("writing the network configuration")?;
    }
    Ok(action)
}

pub(crate) fn init_ipv6_prefix() -> anyhow::Result<()> {
    match persist_prefix(aether::random::fill_public)? {
        PrefixAction::Existing(prefix) => {
            println!("IPv6 tunnel prefix already configured: {prefix}");
        }
        PrefixAction::Generated(prefix) => {
            println!("IPv6 tunnel prefix configured: {prefix}");
            println!("Restart heliosd to apply the tunnel prefix.");
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs, path::Path};

    fn with_config<T>(raw: &str, body: impl FnOnce(&Path) -> T) -> T {
        let dir = std::env::temp_dir().join(format!(
            "helios-ipv6-prefix-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("temporary config directory");
        let path = dir.join("network.toml");
        fs::write(&path, raw).expect("initial config");
        let result = crate::with_network_config_test(&path, || body(&path));
        fs::remove_dir_all(dir).expect("remove temporary config directory");
        result
    }

    #[test]
    fn generates_valid_prefix_and_persists_it_to_network_config() {
        with_config("", |path| {
            let action = persist_prefix(|out| {
                assert_eq!(out.len(), 5);
                out.copy_from_slice(&[0x3c, 0x91, 0xa2, 0x7e, 0x04]);
                Ok::<_, &'static str>(())
            })
            .expect("prefix generation");
            let prefix: TunnelPrefixV6 = "fd3c:91a2:7e04::1/64".parse().expect("valid prefix");
            assert_eq!(action, PrefixAction::Generated(prefix));
            assert!(fs::read_to_string(path)
                .expect("read config")
                .contains("wg_address_v6 = \"fd3c:91a2:7e04::1/64\""));
            assert_eq!(NetworkConfig::load().unwrap().wg_address_v6, Some(prefix));
        });
    }

    #[test]
    fn existing_prefix_does_not_draw_or_rewrite_config() {
        let raw = "wg_address_v6 = \"fd00:1:2::1/64\"\n";
        with_config(raw, |path| {
            let before = fs::read(path).expect("read original config");
            let action = persist_prefix(|_| -> Result<(), &'static str> {
                panic!("existing prefix must not draw randomness")
            })
            .expect("existing prefix");
            assert_eq!(
                action,
                PrefixAction::Existing("fd00:1:2::1/64".parse().unwrap())
            );
            assert_eq!(fs::read(path).expect("read config"), before);
        });
    }

    #[test]
    fn rng_failure_leaves_config_unchanged() {
        let raw = "wg_address = \"100.64.0.1/10\"\n";
        with_config(raw, |path| {
            let before = fs::read(path).expect("read original config");
            let action = persist_prefix(|_| Err("unavailable"));
            assert!(action.unwrap_err().to_string().contains("unavailable"));
            assert_eq!(NetworkConfig::load().unwrap().wg_address_v6, None);
            assert_eq!(fs::read(path).expect("read config"), before);
        });
    }

    #[test]
    fn save_refusal_preserves_config_with_legacy_private_key() {
        let raw = "wg_private_key = \"cHJpdmF0ZQ==\"\n";
        with_config(raw, |path| {
            let before = fs::read(path).expect("read original config");
            let result = persist_prefix(|out| {
                out.copy_from_slice(&[0x3c, 0x91, 0xa2, 0x7e, 0x04]);
                Ok::<_, &'static str>(())
            });
            assert!(result.is_err());
            assert_eq!(fs::read(path).expect("read config"), before);
        });
    }
}
