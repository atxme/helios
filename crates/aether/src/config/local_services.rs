//! What `[[local_services]]` refuses.
//!
//! The rule a service produces names an interface, two addresses and a port.
//! Everything here keeps that rule as narrow as it reads: an interface that
//! already has a role, a public address or an Astra coordinate would turn an
//! opening toward one container into an opening toward something else.

use std::net::Ipv4Addr;

use super::NetworkConfig;
use crate::error::{HeliosError, Result};
use crate::policy::LocalService;

/// More than a gateway needs, few enough to read in a ruleset.
const MAX_LOCAL_SERVICES: usize = 4;

const MAX_NAME_LEN: usize = 32;

/// `IFNAMSIZ` minus its terminating zero.
const MAX_IFACE_LEN: usize = 15;

/// Interfaces whose rules Helios fixes itself (`helios-firewall`,
/// `ruleset/astra_channel.rs`), plus the loopback.
const RESERVED_IFACES: [&str; 3] = ["lo", "astra0", "astra1"];

/// Both Astra bridges: `10.88.7.0/29` and `10.88.7.8/29`.
const ASTRA_NETWORK: &str = "10.88.7.0/28";

impl NetworkConfig {
    /// Refuses a service whose rule would open more than it says.
    pub(super) fn validate_local_services(&self) -> Result<()> {
        if self.local_services.len() > MAX_LOCAL_SERVICES {
            return Err(refuse(format!(
                "at most {MAX_LOCAL_SERVICES} services may be declared"
            )));
        }
        for (index, service) in self.local_services.iter().enumerate() {
            self.validate_local_service(service)?;
            for earlier in &self.local_services[..index] {
                if earlier.name == service.name {
                    return Err(refuse(format!("name {} is declared twice", service.name)));
                }
                if earlier.iface == service.iface {
                    return Err(refuse(format!(
                        "iface {} carries two services",
                        service.iface
                    )));
                }
                if (earlier.peer, earlier.port) == (service.peer, service.port) {
                    return Err(refuse(format!(
                        "{}:{} is declared twice",
                        service.peer, service.port
                    )));
                }
            }
        }
        Ok(())
    }

    fn validate_local_service(&self, service: &LocalService) -> Result<()> {
        if !valid_name(&service.name) {
            return Err(refuse(format!(
                "name {:?} must be 1 to {MAX_NAME_LEN} lowercase letters, digits or hyphens",
                service.name
            )));
        }
        let iface = service.iface.as_str();
        if !valid_iface(iface) {
            return Err(refuse(format!(
                "iface {iface:?} must be an exact interface name of at most {MAX_IFACE_LEN} \
                 characters, without wildcard"
            )));
        }
        if let Some(role) = self.role_of(iface) {
            return Err(refuse(format!(
                "iface {iface} is {role}; a service needs a bridge of its own"
            )));
        }
        for address in [service.host, service.peer] {
            self.validate_service_address(address)?;
        }
        if service.host == service.peer {
            return Err(refuse(format!(
                "host and peer must be distinct, both are {}",
                service.host
            )));
        }
        if service.port == 0 {
            return Err(refuse("port must not be zero".into()));
        }
        Ok(())
    }

    fn validate_service_address(&self, address: Ipv4Addr) -> Result<()> {
        if !address.is_private() {
            return Err(refuse(format!(
                "{address} is not a private address (RFC 1918)"
            )));
        }
        let text = address.to_string();
        if Self::cidr_contains(ASTRA_NETWORK, &text) {
            return Err(refuse(format!(
                "{address} belongs to the Astra bridges ({ASTRA_NETWORK})"
            )));
        }
        if Self::cidr_contains(&self.wg_address, &text) {
            return Err(refuse(format!(
                "{address} is inside the Helios tunnel network {}",
                self.wg_address
            )));
        }
        Ok(())
    }

    /// The role `iface` already has in this configuration, if any.
    fn role_of(&self, iface: &str) -> Option<&'static str> {
        let named = |ifaces: &[String]| ifaces.iter().any(|other| other.trim() == iface);
        if RESERVED_IFACES.contains(&iface) {
            Some("reserved by Helios")
        } else if self.wg_iface.trim() == iface {
            Some("the Helios tunnel interface")
        } else if named(&self.wan_ifaces) {
            Some("a WAN interface")
        } else if named(&self.lan_ifaces) {
            Some("a LAN interface")
        } else if named(&self.admin_ifaces)
            || self
                .admin_iface
                .as_deref()
                .is_some_and(|admin| admin.trim() == iface)
        {
            Some("an administration interface")
        } else if self
            .nordvpn_meshnet
            .as_ref()
            .is_some_and(|meshnet| meshnet.iface.trim() == iface)
        {
            Some("the Meshnet interface")
        } else {
            None
        }
    }
}

fn refuse(reason: String) -> HeliosError {
    HeliosError::Config(format!("local_services: {reason}"))
}

fn valid_name(name: &str) -> bool {
    (1..=MAX_NAME_LEN).contains(&name.len())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_iface(iface: &str) -> bool {
    (1..=MAX_IFACE_LEN).contains(&iface.len())
        && iface.as_bytes()[0].is_ascii_alphanumeric()
        && iface
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}
