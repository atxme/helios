//! The two bridges between the gateway and the Astra authority.
//!
//! The private lifecycle channel and the public origin, each pinned to a
//! fixed interface and address pair. Both are rendered unconditionally: they
//! are harmless when the bridges do not exist, and the public one carries the
//! recovery path of ADR-008 §7.5, which must work when the tunnel does not.

use super::ChainKind::{Input, Output};
use super::{Match, Rule, Verdict, L4};

/// Fixed, host-visible bridge of the Astra private channel (spec §8.3).
///
/// Compose gives the bridge this exact name; keeping the tuple here avoids an
/// interface wildcard turning a source-spoofed packet into an authority call.
const ASTRA_PRIVATE_IFACE: &str = "astra0";
const ASTRA_PRIVATE_HOST: &str = "10.88.7.1/32";
const ASTRA_PRIVATE_PEER: &str = "10.88.7.2/32";
const HELIOS_LIFECYCLE_PORT: u16 = 8444;
const ASTRA_LIFECYCLE_PORT: u16 = 8445;

/// Fixed bridge of the Astra **public** origin, and its two coordinates.
///
/// Named for the same reason `astra0` is: compose pins the bridge and the
/// addresses, so the opening below can state all four coordinates instead of
/// wildcarding an interface Docker renames on every recreation.
///
/// The origin is published on `127.0.0.1:8443`, which Docker DNATs onto this
/// bridge. Without this rule the translated packet leaves through `astra1`,
/// matches nothing in a chain whose policy is `drop`, and dies — so the
/// authority's own machine cannot reach the authority. That is what blocks
/// the expired-identity recovery of ADR-008 §7.5, whose whole point is to be
/// reachable when the tunnel is not.
const ASTRA_PUBLIC_IFACE: &str = "astra1";
const ASTRA_PUBLIC_HOST: &str = "10.88.7.9/32";
const ASTRA_PUBLIC_PEER: &str = "10.88.7.10/32";
const ASTRA_ORIGIN_PORT: u16 = 8443;

pub(super) fn lifecycle_and_public_origin(rules: &mut Vec<Rule>) {
    // ── Private Astra ↔ Helios lifecycle channel ───────────────────────────
    // These openings name all four coordinates: interface, source, target and
    // port. They are harmless when the optional bridge does not exist and do
    // not grant the container any forwarding or general host access.
    rules.push(
        Rule::new(
            Input,
            vec![
                Match::InIface(ASTRA_PRIVATE_IFACE.into()),
                Match::SourceNet(ASTRA_PRIVATE_PEER.into()),
                Match::DestNet(ASTRA_PRIVATE_HOST.into()),
                Match::DestPort {
                    port: HELIOS_LIFECYCLE_PORT,
                    proto: L4::Tcp,
                },
            ],
            Verdict::Accept,
        )
        .with_note("Astra mTLS client to the private Helios lifecycle API"),
    );
    rules.push(
        Rule::new(
            Output,
            vec![
                Match::OutIface(ASTRA_PRIVATE_IFACE.into()),
                Match::SourceNet(ASTRA_PRIVATE_HOST.into()),
                Match::DestNet(ASTRA_PRIVATE_PEER.into()),
                Match::DestPort {
                    port: ASTRA_LIFECYCLE_PORT,
                    proto: L4::Tcp,
                },
            ],
            Verdict::Accept,
        )
        .with_note("Helios mTLS client to the private Astra lifecycle API"),
    );
    // The gateway reaching the authority's public origin, on its own machine.
    //
    // Output only, and scoped to the container: nothing here lets the origin
    // out to the WAN, and nothing lets a third party in. `forward` stays
    // `drop`, so the container gains no route through the gateway either —
    // the opening is the host's, not Astra's.
    rules.push(
        Rule::new(
            Output,
            vec![
                Match::OutIface(ASTRA_PUBLIC_IFACE.into()),
                Match::SourceNet(ASTRA_PUBLIC_HOST.into()),
                Match::DestNet(ASTRA_PUBLIC_PEER.into()),
                Match::DestPort {
                    port: ASTRA_ORIGIN_PORT,
                    proto: L4::Tcp,
                },
            ],
            Verdict::Accept,
        )
        .with_note("Helios client to the public Astra origin, published on loopback"),
    );
}
