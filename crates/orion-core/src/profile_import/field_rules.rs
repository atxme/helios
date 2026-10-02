//! Field-by-field rules, each one about a single value and nothing else:
//! no profile, no document.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result};
use base64::Engine as _;

/// Length of a WireGuard key: 32 raw bytes…
const WG_KEY_BYTES: usize = 32;
/// …i.e. exactly 44 characters once base64-encoded.
const WG_KEY_BASE64_LEN: usize = 44;

/// Validates a base64-encoded Curve25519 key.
///
/// The messages say what's expected, not just that it's refused: "base64
/// expected" doesn't help anyone see that a character is missing at the end
/// of a truncated copy-paste. The observed length is given so it can be
/// compared at a glance to the expected 44 characters.
pub(super) fn validate_wg_key(value: &str, label: &str) -> Result<()> {
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(value) else {
        anyhow::bail!(
            "{label} : caractères invalides. Une clé WireGuard fait {WG_KEY_BASE64_LEN} caractères base64 (A–Z, a–z, 0–9, + et /) et se termine par « = »."
        );
    };
    if decoded.len() != WG_KEY_BYTES {
        anyhow::bail!(
            "{label} : {} caractères au lieu de {WG_KEY_BASE64_LEN}. Une clé WireGuard fait {WG_KEY_BYTES} octets et se termine par « = » — vérifier que le copier-coller est complet.",
            value.chars().count()
        );
    }
    Ok(())
}

pub(super) fn validate_endpoint(endpoint: &str) -> Result<()> {
    if endpoint.contains("://") {
        anyhow::bail!("Endpoint doit être une adresse UDP IP/FQDN:port, pas une URL");
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        anyhow::bail!("Endpoint invalide : port UDP absent");
    };
    if host.trim_matches(['[', ']']).is_empty() {
        anyhow::bail!("Endpoint invalide : hôte absent");
    }
    if host.chars().any(char::is_whitespace) {
        anyhow::bail!("Endpoint invalide : l'hôte contient un espace");
    }
    if host.starts_with('[') != host.ends_with(']') {
        anyhow::bail!("Endpoint invalide : adresse IPv6 mal délimitée");
    }
    let port = port
        .parse::<u16>()
        .context("Endpoint invalide : port UDP non numérique")?;
    if port == 0 {
        anyhow::bail!("Endpoint invalide : le port UDP doit être supérieur à zéro");
    }
    validate_endpoint_host(host)
}

/// Validates an endpoint's host: IPv6 literal in brackets, IPv4 address, or
/// hostname.
///
/// The case that motivates this function: `86.229.1286` is **neither** a
/// valid IPv4 (1286 exceeds 255) **nor** a legitimate hostname — RFC 1123
/// forbids a last label from being entirely numeric, precisely so the two
/// can't be confused. Without this rule, a mistyped IPv4 passes for a domain
/// name and the defect only shows up at the first handshake, as a failing
/// DNS resolution.
fn validate_endpoint_host(host: &str) -> Result<()> {
    if let Some(inner) = host
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inner
            .parse::<Ipv6Addr>()
            .map(|_| ())
            .map_err(|_| anyhow::anyhow!("Endpoint invalide : adresse IPv6 illisible"));
    }
    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }

    if host.len() > 253 {
        anyhow::bail!("Endpoint invalide : nom d'hôte trop long");
    }
    let labels: Vec<&str> = host.split('.').collect();
    for label in &labels {
        if label.is_empty() {
            anyhow::bail!("Endpoint invalide : nom d'hôte mal formé");
        }
        if label.len() > 63 {
            anyhow::bail!("Endpoint invalide : partie de nom d'hôte trop longue");
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            anyhow::bail!("Endpoint invalide : caractère interdit dans le nom d'hôte");
        }
        if label.starts_with('-') || label.ends_with('-') {
            anyhow::bail!("Endpoint invalide : nom d'hôte mal formé");
        }
    }
    if labels
        .last()
        .is_some_and(|label| label.chars().all(|c| c.is_ascii_digit()))
    {
        anyhow::bail!("Endpoint invalide : adresse IP mal formée");
    }
    Ok(())
}

/// Splits a comma-separated prefix list into its trimmed, non-empty entries.
///
/// One place, because four call sites read this field — validation, import,
/// the screen and the backend that builds the peer — and a list they parsed
/// differently would let the UI approve a route WireGuard never installs.
pub fn split_cidr_list(value: &str) -> Vec<&str> {
    value
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .collect()
}

/// How much of each address family an `AllowedIPs` list sends into the tunnel.
///
/// Only the whole-family entries count — a prefix of length zero, `0.0.0.0/0`
/// or `::/0` — because they are what decides whether anything of that family
/// can still leave through the physical interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelCapture {
    /// Both families captured whole: the full tunnel.
    Full,
    /// All of IPv4, but no whole-family IPv6 entry: IPv6 leaves in clear.
    ///
    /// Not a split tunnel. It is what the full tunnel used to be, before
    /// [`crate::DEFAULT_ALLOWED_IPS`] added `::/0`, and a profile still holding
    /// it believes it is protected when half of its traffic is not.
    Ipv4Only,
    /// Anything else: a tunnel narrowed on purpose, which is the operator's
    /// decision and not a defect.
    Partial,
}

/// Classifies a prefix list by what it captures whole, family by family.
///
/// Entries are read as [`split_cidr_list`] and [`validate_cidr`] read them, so
/// the classification never contradicts validation; an entry validation would
/// refuse captures nothing here. The Orion screen mirrors this rule for the
/// draft being typed (`apps/orion/src/splitTunnel.ts`), and its tests pin the
/// same cases as this module's.
pub fn tunnel_capture(value: &str) -> TunnelCapture {
    let mut ipv4 = false;
    let mut ipv6 = false;
    for entry in split_cidr_list(value) {
        let Some((address, prefix)) = entry.split_once('/') else {
            continue;
        };
        let (Ok(address), Ok(0)) = (address.parse::<IpAddr>(), prefix.parse::<u8>()) else {
            continue;
        };
        match address {
            IpAddr::V4(_) => ipv4 = true,
            IpAddr::V6(_) => ipv6 = true,
        }
    }
    match (ipv4, ipv6) {
        (true, true) => TunnelCapture::Full,
        (true, false) => TunnelCapture::Ipv4Only,
        _ => TunnelCapture::Partial,
    }
}

/// Validates a list of prefixes: `AllowedIPs` is one, an address is not.
///
/// # Why several
///
/// `AllowedIPs` is WireGuard's cryptographic routing table, and a split
/// tunnel usually needs more than one entry — the VPN network *and* the
/// remote LAN, say, which have no common supernet short of `0.0.0.0/0`.
/// Accepting a single prefix forced the choice between them, or the whole
/// Internet. A `wg-quick` file, where a comma-separated list is the ordinary
/// form, was refused for the same reason.
///
/// Each entry is validated on its own and named in the message: "the third is
/// wrong" is what turns a rejected list into a fixed one.
/// Validates an SSH destination: `user@host`, `host`, optionally `:port`.
///
/// # An allow-list, and why it has to be one
///
/// This value ends up as an **argument of a spawned process**. Every other
/// field of a profile is data the client interprets itself; this one crosses
/// into the operating system. A profile document arrives from outside — an
/// operator's file, an email attachment, a double-clicked download — so the
/// question is not whether the string looks reasonable but whether anything
/// it could contain can mean something to a shell.
///
/// Hence an allow-list of characters rather than a deny-list of dangerous
/// ones: letters, digits, `.`, `-`, `_`, one optional `@`, one optional `:`
/// followed by digits. No space, no quote, no `;`, `&`, `|`, `$`, backtick,
/// newline, and no leading `-` that an argument parser would read as a flag.
/// A deny-list is a promise to have thought of every metacharacter of every
/// shell the launcher might one day use; this is a promise about what is
/// allowed, which stays true when the launcher changes.
pub fn validate_ssh_target(value: &str) -> Result<()> {
    let value = value.trim();
    if value.is_empty() {
        anyhow::bail!("destination SSH vide");
    }
    if value.len() > 255 {
        anyhow::bail!("destination SSH trop longue");
    }
    let (user_host, port) = match value.rsplit_once(':') {
        Some((rest, port)) => (rest, Some(port)),
        None => (value, None),
    };
    if let Some(port) = port {
        let port: u16 = port
            .parse()
            .context("destination SSH invalide : port non numérique")?;
        if port == 0 {
            anyhow::bail!("destination SSH invalide : port nul");
        }
    }
    let host = match user_host.split_once('@') {
        Some((user, host)) => {
            if user.is_empty() {
                anyhow::bail!("destination SSH invalide : nom d'utilisateur vide");
            }
            if !user
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            {
                anyhow::bail!(
                    "destination SSH invalide : le nom d'utilisateur n'accepte que lettres, \
                     chiffres, point, tiret et souligné"
                );
            }
            host
        }
        None => user_host,
    };
    if host.is_empty() {
        anyhow::bail!("destination SSH invalide : hôte vide");
    }
    if host.contains('@') {
        anyhow::bail!("destination SSH invalide : un seul « @ » est attendu");
    }
    if !host
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
    {
        anyhow::bail!(
            "destination SSH invalide : l'hôte n'accepte que lettres, chiffres, point, \
             tiret et souligné — ni espace ni caractère de shell"
        );
    }
    // A leading dash would be read as an option by `ssh` itself, whatever the
    // launcher does with quoting.
    if value.starts_with('-') || host.starts_with('-') {
        anyhow::bail!("destination SSH invalide : elle ne peut pas commencer par « - »");
    }
    Ok(())
}

/// Public entry point for tooling that emits a profile document.
///
/// `helios-ctl` validates the operator's `--allowed-ips` **before** admitting
/// a peer, so a mistyped prefix is a refusal rather than an admission with no
/// usable profile behind it.
pub fn validate_allowed_ips(value: &str) -> Result<()> {
    validate_cidr_list(value, "trafic capté")
}

pub(super) fn validate_cidr_list(value: &str, label: &str) -> Result<()> {
    let entries = split_cidr_list(value);
    if entries.is_empty() {
        anyhow::bail!("{label} invalide : au moins un préfixe est requis");
    }
    for (index, entry) in entries.iter().enumerate() {
        validate_cidr(entry, label).with_context(|| {
            if entries.len() > 1 {
                format!("{label} : préfixe {} sur {}", index + 1, entries.len())
            } else {
                label.to_string()
            }
        })?;
    }
    // Duplicates are refused rather than silently collapsed. WireGuard would
    // take the list as it comes, so a prefix written twice is not an ambiguity
    // to arbitrate — it is a list the user has lost track of, and the second
    // occurrence is usually a typo for something else.
    for (index, entry) in entries.iter().enumerate() {
        if entries[..index].contains(entry) {
            anyhow::bail!("{label} invalide : le préfixe {entry} apparaît deux fois");
        }
    }
    Ok(())
}

/// Rewrites a prefix list in one canonical form: `a/n, b/m`.
///
/// The screen, the stored profile and the peer built from it must agree
/// character for character — otherwise a profile saved as `a/n,b/m` and
/// redisplayed as `a/n, b/m` reads as an unsaved change on every load.
pub fn normalize_cidr_list(value: &str) -> String {
    split_cidr_list(value).join(", ")
}

pub(super) fn validate_cidr(value: &str, label: &str) -> Result<()> {
    let Some((address, prefix)) = value.split_once('/') else {
        anyhow::bail!("{label} invalide : notation CIDR attendue");
    };
    let address = address
        .parse::<IpAddr>()
        .with_context(|| format!("{label} invalide : adresse IP illisible"))?;
    let prefix = prefix
        .parse::<u8>()
        .with_context(|| format!("{label} invalide : préfixe non numérique"))?;
    let max_prefix = if address.is_ipv4() { 32 } else { 128 };
    if prefix > max_prefix {
        anyhow::bail!("{label} invalide : préfixe supérieur à {max_prefix}");
    }
    Ok(())
}

/// Validates the tunnel IPv6 address: one host, written `…/128`
/// (`ADRESSAGE-IPV6.md` §2.3).
///
/// The rule is [`aether::net::parse_vip_v6`], the one the gateway reads its
/// own `address_v6` with, so a value Orion accepts is one the gateway could
/// have written. Never a `/64`: a peer free to pick its source inside a prefix
/// would make the source → peer association ambiguous. Only the messages are
/// Orion's, because they are displayed as-is on screen.
///
/// Whether the address belongs to the gateway's prefix is not checked here:
/// the prefix is gateway configuration, which a profile does not carry.
pub fn validate_address_v6(value: &str) -> Result<()> {
    use aether::net::AddressError;

    let Err(error) = aether::net::parse_vip_v6(value.trim()) else {
        return Ok(());
    };
    let reason = match &error {
        AddressError::ZoneId(_) => "identifiant de zone (« % ») interdit : une adresse du \
                                    tunnel n'appartient à aucun lien local"
            .to_string(),
        AddressError::MissingPrefixLength(_) => "notation …/128 attendue".to_string(),
        AddressError::InvalidPrefixLength(_) => {
            "longueur de préfixe illisible, /128 attendu".to_string()
        }
        AddressError::InvalidAddress(_) => "adresse IP illisible".to_string(),
        AddressError::NotIpv6(v4) => {
            format!("{v4} est une adresse IPv4, sa place est dans l'adresse virtuelle")
        }
        AddressError::WrongPrefixLength { found, .. } => format!(
            "/{found} au lieu de /128 : un poste a une seule adresse IPv6, jamais un préfixe"
        ),
        other => other.to_string(),
    };
    anyhow::bail!("adresse IPv6 invalide : {reason}")
}

/// Checks the IPv6 address, and checks it against the address it accompanies.
///
/// The IPv6 address is the **second** address of the tunnel, never its only
/// one: identity and control plane stay IPv4 (`ADRESSAGE-IPV6.md` §2.6), and a
/// virtual address that is itself IPv6 would put two IPv6 addresses on the
/// adapter with nothing to say which one the gateway knows. An absent virtual
/// address is not judged here — an invitation arrives without one.
pub(super) fn validate_address_pair(address: Option<&str>, address_v6: &str) -> Result<()> {
    validate_address_v6(address_v6)?;
    let address_is_v6 = address
        .and_then(|value| value.split_once('/'))
        .and_then(|(host, _)| host.trim().parse::<IpAddr>().ok())
        .is_some_and(|host| host.is_ipv6());
    if address_is_v6 {
        anyhow::bail!(
            "adresse IPv6 invalide : l'adresse virtuelle est déjà une adresse IPv6, alors que \
             l'adresse IPv6 accompagne une adresse virtuelle IPv4"
        );
    }
    Ok(())
}

/// Sorts the `Address` of a `wg-quick` file into the profile's two fields.
///
/// - one entry, whatever its family: the virtual address, as it was always
///   read — a file that imported before this function still imports the same;
/// - two entries, one IPv4 and one IPv6: the virtual address and the IPv6
///   address, which [`validate_address_v6`] then holds to `/128`;
/// - anything else is refused by name. Two addresses of one family leave a
///   choice the file does not make, and the profile has one slot per family:
///   picking one would mount a tunnel the file does not describe.
pub(super) fn split_interface_address(value: &str) -> Result<(Option<String>, Option<String>)> {
    let entries = split_cidr_list(value);
    if entries.len() <= 1 {
        return Ok((entries.first().map(|entry| entry.to_string()), None));
    }
    let mut ipv4: Vec<&str> = Vec::new();
    let mut ipv6: Vec<&str> = Vec::new();
    for entry in &entries {
        let host = entry.split_once('/').map_or(*entry, |(host, _)| host);
        match host.trim().parse::<IpAddr>() {
            Ok(IpAddr::V4(_)) => ipv4.push(entry),
            Ok(IpAddr::V6(_)) => ipv6.push(entry),
            Err(_) => anyhow::bail!("Address invalide : « {entry} » n'est pas une adresse IP"),
        }
    }
    for (family, found) in [("IPv4", &ipv4), ("IPv6", &ipv6)] {
        if found.len() > 1 {
            anyhow::bail!(
                "Address porte plusieurs adresses {family} ({}) : Orion en pose une seule par \
                 famille, et choisir laquelle reviendrait à deviner",
                found.join(", ")
            );
        }
    }
    Ok((
        ipv4.first().map(|entry| entry.to_string()),
        ipv6.first().map(|entry| entry.to_string()),
    ))
}

pub(super) fn validate_heliosd_url(url: &str) -> Result<()> {
    let rest = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("https://"))
        .context("URL Helios interne invalide : schéma http:// ou https:// attendu")?;
    if rest.is_empty() || rest.chars().any(char::is_whitespace) {
        anyhow::bail!("URL Helios interne invalide");
    }
    Ok(())
}
