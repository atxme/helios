//! The gateway's own identity: freeze it, then let the signed transition go.
//!
//! Both read or write state the registry has never held — the leaves the
//! daemon actually serves — so both use the running service's own channel to
//! the gateway, through the door. With the service stopped, the publication
//! still runs here, under the volume lock, on the channel the service is
//! configured with.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use astra::door::{
    DoorOutcome, DoorRequest, OpenedSubject, Opening, GATEWAY_ACTIVE_CERTIFICATE_FILE,
};

use crate::{console, now_unix};

/// Freezes the gateway identity in service into a signing campaign (§11.1 3).
pub(crate) fn gateway_identity_open(
    state_dir: &Path,
    reason: &str,
    requested_by: &str,
    window_secs: u64,
) -> Result<()> {
    let text = console::opening_text(reason, requested_by, window_secs);
    let opening = console::opened(console::open(
        state_dir,
        DoorRequest::GatewayIdentity { text },
    )?)?;
    print_gateway_identity(state_dir, &opening, window_secs)
}

/// What a gateway-identity campaign prints, alone or as a step of the chain.
pub(super) fn print_gateway_identity(
    state_dir: &Path,
    opening: &Opening,
    window_secs: u64,
) -> Result<()> {
    let OpenedSubject::Gateway {
        decision_epoch,
        tls_certificate_fingerprint,
        pq_certificate_fingerprint,
    } = &opening.subject
    else {
        return Err(console::unexpected(&DoorOutcome::Opened(opening.clone())));
    };
    let next_epoch = decision_epoch
        .checked_add(1)
        .context("gateway decision epoch overflow")?;
    let operation_id = opening.opened.operation_id;
    // The door exported the leaf in service beside the registry, at a name it
    // chose: this is the same volume, reached by the same socket.
    let served_path = state_dir.join(GATEWAY_ACTIVE_CERTIFICATE_FILE);
    println!("{}", operation_id.to_hex());
    eprintln!("campagne gateway déposée : décision {decision_epoch}, fenêtre de {window_secs} s");
    eprintln!("feuille PQ en service : {pq_certificate_fingerprint}");
    eprintln!("feuille TLS en service : {tls_certificate_fingerprint}");
    eprintln!(
        "empreinte de campagne : {}",
        opening.opened.campaign_fingerprint
    );
    eprintln!("feuille en service exportée : {}", served_path.display());
    eprintln!("renouveler dans Orion : Astra › Rotations (époque {next_epoch})");
    eprintln!(
        "ou annuler la transition déjà en attente : Astra › Rotations, opération {}",
        operation_id.to_hex()
    );
    Ok(())
}

/// Lets a signed transition leave the authority (spec §11.1 step 6).
///
/// Replayable: the mark is persisted before the relay, and a second run
/// finishes a relay the first could not confirm.
pub(crate) fn gateway_identity_publish(
    state_dir: &Path,
    epoch: u64,
    transition: &str,
) -> Result<()> {
    let transition_fingerprint =
        super::trust_domain::parse_fingerprint(transition).context("--transition")?;
    let outcome = console::write(
        state_dir,
        DoorRequest::GatewayIdentityPublish {
            epoch,
            transition_fingerprint,
        },
        |registry| {
            let channel = configured_gateway_channel(state_dir)?;
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("starting a runtime for the private channel")?;
            let (mark, confirmed) =
                runtime.block_on(astra::door::write::publish_gateway_transition(
                    registry,
                    &channel,
                    epoch,
                    &transition_fingerprint,
                    now_unix(),
                ))?;
            Ok(DoorOutcome::published(mark, confirmed))
        },
    )?;
    let DoorOutcome::Published {
        epoch,
        transition_fingerprint,
        activation_at,
        confirmed,
    } = outcome
    else {
        return Err(console::unexpected(&outcome));
    };
    if !confirmed {
        anyhow::bail!(
            "the publication is recorded here but the gateway did not confirm it; re-run this \
             command"
        );
    }
    println!("{transition_fingerprint}");
    eprintln!("transition publiée : époque {epoch}, activation {activation_at}");
    eprintln!("l'avortement n'est plus légitime ; la distribution aux clients est ouverte");
    Ok(())
}

/// The channel `astra run` is configured with, for a publication made while
/// it is stopped.
///
/// Read from the service's own variables (`ASTRA_GATEWAY_CHANNEL`,
/// `ASTRA_GATEWAY_CERTIFICATE`, as `astra run` reads them) rather than from a
/// flag: the gateway a publication reaches is the service's, whichever path
/// the write takes.
fn configured_gateway_channel(state_dir: &Path) -> Result<astra::gateway::GatewayChannel> {
    configured_gateway_channel_from(
        state_dir,
        std::env::var("ASTRA_GATEWAY_CHANNEL").ok().as_deref(),
        std::env::var("ASTRA_GATEWAY_CERTIFICATE").ok().as_deref(),
    )
}

fn configured_gateway_channel_from(
    state_dir: &Path,
    address: Option<&str>,
    certificate: Option<&str>,
) -> Result<astra::gateway::GatewayChannel> {
    let (Some(address), Some(certificate)) = (address, certificate) else {
        return Err(astra::door::DoorRefusal::PublicationChannelUnavailable.into());
    };
    let address: SocketAddr = address
        .parse()
        .context("ASTRA_GATEWAY_CHANNEL n'est pas une adresse")?;
    let pinned = aether::certificates::encoding::DerCertificate::parse(certificate)
        .map_err(|error| anyhow::anyhow!("ASTRA_GATEWAY_CERTIFICATE illisible : {error}"))?;
    astra::gateway::GatewayChannel::open(state_dir, address, &pinned)
        .map_err(|error| anyhow::anyhow!("ouvrir le canal privé vers la gateway : {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::certificates::{
        encoding::{Fingerprint, Id16},
        status::CampaignScope,
        transport::OperatorOpened,
    };

    fn opening(subject: OpenedSubject) -> Opening {
        Opening {
            opened: OperatorOpened {
                operation_id: Id16::new([1; 16]).expect("nonzero operation id"),
                campaign_id: Id16::new([2; 16]).expect("nonzero campaign id"),
                campaign_fingerprint: Fingerprint::from_bytes([3; 32]),
                scope: CampaignScope::GatewayIdentity,
                target_count: 1,
                required_credentials: 1,
                expires_at: 100,
                revocation_expiries: None,
                delegation_request: None,
                gateway_certificate: None,
            },
            authority_url: "https://astra.example".into(),
            subject,
        }
    }

    fn gateway_subject(decision_epoch: u64) -> OpenedSubject {
        OpenedSubject::Gateway {
            decision_epoch,
            tls_certificate_fingerprint: Fingerprint::from_bytes([4; 32]),
            pq_certificate_fingerprint: Fingerprint::from_bytes([5; 32]),
        }
    }

    #[test]
    fn prints_a_gateway_identity_opening() {
        let state_dir = tempfile::tempdir().expect("temporary state directory");
        let result = print_gateway_identity(state_dir.path(), &opening(gateway_subject(8)), 120);
        assert!(result.is_ok());
    }

    #[test]
    fn refuses_a_door_response_for_another_subject() {
        let state_dir = tempfile::tempdir().expect("temporary state directory");
        let result = print_gateway_identity(state_dir.path(), &opening(OpenedSubject::Domain), 120);
        assert!(result.is_err());
    }

    #[cfg(unix)]
    fn mock_door(state_dir: &Path, outcome: DoorOutcome) -> std::thread::JoinHandle<DoorRequest> {
        use std::io::{Read as _, Write as _};
        use std::os::unix::net::UnixListener;
        use std::time::{Duration, Instant};

        let listener = UnixListener::bind(state_dir.join(astra::door::DOOR_SOCKET_FILE))
            .expect("bind isolated mock door");
        listener
            .set_nonblocking(true)
            .expect("bound listener supports nonblocking accept");
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(5);
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "console did not connect to mock door"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                    Err(error) => panic!("accept console request: {error}"),
                }
            };
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("bound mock stream reads");
            let mut request = Vec::new();
            let mut buffer = [0; 1024];
            let body_start = loop {
                let read = stream.read(&mut buffer).expect("read console request");
                assert_ne!(read, 0, "console closed before sending a request");
                request.extend_from_slice(&buffer[..read]);
                if let Some(index) = request.windows(4).position(|window| window == b"\r\n\r\n") {
                    break index + 4;
                }
            };
            let headers = std::str::from_utf8(&request[..body_start]).expect("HTTP headers");
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().expect("content length"))
                })
                .expect("content-length header");
            while request.len() < body_start + content_length {
                let read = stream.read(&mut buffer).expect("read console body");
                assert_ne!(read, 0, "console closed before sending its full body");
                request.extend_from_slice(&buffer[..read]);
            }
            let parsed: DoorRequest =
                serde_json::from_slice(&request[body_start..body_start + content_length])
                    .expect("typed door request");
            let response = serde_json::to_vec(&outcome).expect("serialize door outcome");
            write!(
                stream,
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                response.len()
            )
            .expect("write response headers");
            stream.write_all(&response).expect("write door response");
            parsed
        })
    }

    #[cfg(unix)]
    fn publish_from_mock_door(outcome: DoorOutcome) -> (anyhow::Result<()>, DoorRequest) {
        let state_dir = tempfile::tempdir().expect("temporary state directory");
        let _volume = astra::door::VolumeLock::try_acquire(state_dir.path())
            .expect("create volume lock")
            .expect("hold volume lock to route writes through the door");
        let mock = mock_door(state_dir.path(), outcome);
        let result = gateway_identity_publish(state_dir.path(), 9, &"ab".repeat(32));
        let request = mock.join().expect("mock door thread");
        (result, request)
    }

    #[cfg(unix)]
    #[test]
    fn publish_sends_the_typed_request_and_accepts_gateway_confirmation() {
        let outcome = DoorOutcome::Published {
            epoch: 9,
            transition_fingerprint: Fingerprint::from_bytes([0xab; 32]),
            activation_at: 1234,
            confirmed: true,
        };
        let (result, request) = publish_from_mock_door(outcome);
        assert!(result.is_ok(), "{result:?}");
        assert!(matches!(
            request,
            DoorRequest::GatewayIdentityPublish { epoch: 9, transition_fingerprint }
                if transition_fingerprint == Fingerprint::from_bytes([0xab; 32])
        ));
    }

    #[cfg(unix)]
    #[test]
    fn publish_reports_when_the_gateway_has_not_confirmed() {
        let outcome = DoorOutcome::Published {
            epoch: 9,
            transition_fingerprint: Fingerprint::from_bytes([0xab; 32]),
            activation_at: 1234,
            confirmed: false,
        };
        let (result, request) = publish_from_mock_door(outcome);
        let error = result.expect_err("an unconfirmed relay must remain retryable");
        assert!(error.to_string().contains("did not confirm"));
        assert!(matches!(
            request,
            DoorRequest::GatewayIdentityPublish { epoch: 9, .. }
        ));
    }

    #[cfg(unix)]
    #[test]
    fn publish_rejects_an_unrelated_door_reply() {
        let outcome = DoorOutcome::Pinned {
            audit_head: Fingerprint::from_bytes([8; 32]),
            changed: true,
        };
        let (result, request) = publish_from_mock_door(outcome);
        let error = result.expect_err("a write reply must match the requested publication");
        assert!(error.to_string().contains("a répondu autre chose"));
        assert!(matches!(
            request,
            DoorRequest::GatewayIdentityPublish { .. }
        ));
    }

    #[test]
    fn refuses_missing_private_channel_configuration() {
        let state_dir = tempfile::tempdir().expect("temporary state directory");
        let error = configured_gateway_channel_from(state_dir.path(), None, None)
            .err()
            .expect("publication requires the service's private channel settings");
        assert!(error
            .to_string()
            .contains("canal privé vers la gateway n'est pas disponible"));
    }

    #[test]
    fn refuses_a_malformed_private_channel_address() {
        let state_dir = tempfile::tempdir().expect("temporary state directory");
        let error = configured_gateway_channel_from(
            state_dir.path(),
            Some("not-an-address"),
            Some("certificate"),
        )
        .err()
        .expect("an invalid channel address must fail before opening a socket");
        assert!(error.to_string().contains("ASTRA_GATEWAY_CHANNEL"));
    }

    #[test]
    fn refuses_a_malformed_pinned_certificate() {
        let state_dir = tempfile::tempdir().expect("temporary state directory");
        let error = configured_gateway_channel_from(
            state_dir.path(),
            Some("127.0.0.1:9"),
            Some("not a certificate"),
        )
        .err()
        .expect("an unreadable pin must fail before opening a socket");
        assert!(error.to_string().contains("ASTRA_GATEWAY_CERTIFICATE"));
    }

    #[test]
    fn refuses_to_overflow_the_next_decision_epoch() {
        let state_dir = tempfile::tempdir().expect("temporary state directory");
        let result =
            print_gateway_identity(state_dir.path(), &opening(gateway_subject(u64::MAX)), 120);
        let error = result.expect_err("the next decision epoch must be representable");
        assert!(error
            .to_string()
            .contains("gateway decision epoch overflow"));
    }
}
