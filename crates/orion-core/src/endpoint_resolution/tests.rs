use std::net::SocketAddr;

use super::*;

fn addr(value: &str) -> SocketAddr {
    value.parse().unwrap()
}

fn addrs(values: &[&str]) -> Vec<SocketAddr> {
    values.iter().map(|value| addr(value)).collect()
}

/// The dual-stack case: the resolver sorted IPv6 first, and the families
/// alternate from there, each keeping the resolver's own order.
#[test]
fn families_are_interleaved_starting_with_ipv6() {
    let ordered = rfc8305_order(addrs(&[
        "[2001:db8::1]:51821",
        "[2001:db8::2]:51821",
        "[2001:db8::3]:51821",
        "203.0.113.10:51821",
        "203.0.113.11:51821",
    ]));
    assert_eq!(
        ordered,
        addrs(&[
            "[2001:db8::1]:51821",
            "203.0.113.10:51821",
            "[2001:db8::2]:51821",
            "203.0.113.11:51821",
            "[2001:db8::3]:51821",
        ])
    );
}

/// RFC 8305 §4 keeps the family the resolver put first. A resolver that
/// sorted IPv4 first did so because IPv6 is unusable here (RFC 6724), and
/// overruling it would pin an un-raced tunnel endpoint to the dead family.
#[test]
fn the_family_the_resolver_put_first_leads() {
    let ordered = rfc8305_order(addrs(&[
        "203.0.113.10:51821",
        "203.0.113.11:51821",
        "[2001:db8::1]:51821",
    ]));
    assert_eq!(
        ordered,
        addrs(&[
            "203.0.113.10:51821",
            "[2001:db8::1]:51821",
            "203.0.113.11:51821",
        ])
    );
}

#[test]
fn an_ipv4_only_answer_keeps_its_order() {
    let ordered = rfc8305_order(addrs(&["203.0.113.10:51821", "203.0.113.11:51821"]));
    assert_eq!(
        ordered,
        addrs(&["203.0.113.10:51821", "203.0.113.11:51821"])
    );
}

#[test]
fn an_ipv6_only_answer_keeps_its_order() {
    let ordered = rfc8305_order(addrs(&["[2001:db8::2]:51821", "[2001:db8::1]:51821"]));
    assert_eq!(
        ordered,
        addrs(&["[2001:db8::2]:51821", "[2001:db8::1]:51821"])
    );
}

/// `getaddrinfo` returns one entry per socket type unless told otherwise:
/// the same address several times is one candidate, at its first position.
#[test]
fn duplicates_are_tried_once() {
    let ordered = rfc8305_order(addrs(&[
        "[2001:db8::1]:51821",
        "[2001:db8::1]:51821",
        "203.0.113.10:51821",
        "203.0.113.10:51821",
        "[2001:db8::1]:51821",
    ]));
    assert_eq!(
        ordered,
        addrs(&["[2001:db8::1]:51821", "203.0.113.10:51821"])
    );
}

/// A mapped address is the IPv4 address it carries — and the duplicate of
/// the `A` record when both come back.
#[test]
fn an_ipv4_mapped_address_is_read_as_ipv4() {
    let ordered = rfc8305_order(addrs(&[
        "[::ffff:203.0.113.10]:51821",
        "203.0.113.10:51821",
        "[2001:db8::1]:51821",
    ]));
    assert_eq!(
        ordered,
        addrs(&["203.0.113.10:51821", "[2001:db8::1]:51821"])
    );
}

#[test]
fn a_zero_port_is_never_a_candidate() {
    assert!(rfc8305_order(addrs(&["203.0.113.10:0"])).is_empty());
    assert!(rfc8305_order(Vec::new()).is_empty());
}

/// A literal is its own and only candidate, and no resolver is asked.
#[tokio::test]
async fn a_literal_endpoint_is_its_own_single_candidate() {
    assert_eq!(
        resolve_candidates("[2001:db8::1]:51821").await.unwrap(),
        addrs(&["[2001:db8::1]:51821"])
    );
    assert_eq!(
        resolve_candidates("203.0.113.10:51821").await.unwrap(),
        addrs(&["203.0.113.10:51821"])
    );
    assert_eq!(
        rfc8305_order(addrs(&["203.0.113.10:51821"])),
        addrs(&["203.0.113.10:51821"])
    );
}

#[tokio::test]
async fn a_literal_without_a_usable_port_is_refused_by_name() {
    let error = resolve_candidates("203.0.113.10:0").await.unwrap_err();
    assert!(format!("{error:#}").contains("203.0.113.10:0"), "{error:#}");
}

#[test]
fn the_data_plane_only_takes_literals() {
    assert_eq!(
        literal_endpoint("[2001:db8::1]:51820").unwrap(),
        addr("[2001:db8::1]:51820")
    );
    assert_eq!(
        literal_endpoint("203.0.113.10:51820").unwrap(),
        addr("203.0.113.10:51820")
    );
    assert!(literal_endpoint("gateway.example:51820").is_err());
    assert!(literal_endpoint("2001:db8::1:51820").is_err());
    assert!(literal_endpoint("203.0.113.10:0").is_err());
}

#[test]
fn same_host_ignores_ports_brackets_case_and_a_final_dot() {
    assert!(same_host("gateway.example:51820", "Gateway.Example.:51821"));
    assert!(same_host("[2001:db8::1]:51820", "[2001:db8::1]:51821"));
    assert!(same_host("203.0.113.10:51820", "203.0.113.10:51821"));
    assert!(!same_host("gateway.example:51820", "nego.example:51821"));
    // A name and the address it may resolve to are still two hosts: they
    // are resolved separately, never merged.
    assert!(!same_host("gateway.example:51820", "203.0.113.10:51821"));
    assert!(!same_host("gateway.example", "gateway.example:51821"));
}

#[test]
fn the_port_is_read_from_the_endpoint() {
    assert_eq!(port_of("gateway.example:51820"), Some(51820));
    assert_eq!(port_of("[2001:db8::1]:51820"), Some(51820));
    assert_eq!(port_of("gateway.example:0"), None);
    assert_eq!(port_of("gateway.example"), None);
}

#[test]
fn the_family_is_named() {
    assert_eq!(family(&addr("[2001:db8::1]:51820")), "IPv6");
    assert_eq!(family(&addr("203.0.113.10:51820")), "IPv4");
}

// --- The staggered race, with injected connectors: no socket, no resolver.

const V6: &str = "[2001:db8::1]:51821";
const V4: &str = "203.0.113.10:51821";

type Shared<T> = std::sync::Arc<std::sync::Mutex<Vec<T>>>;

/// Records which candidates were started, and which were dropped unfinished.
#[derive(Default, Clone)]
struct Journal {
    started: Shared<(SocketAddr, Duration)>,
    cancelled: Shared<SocketAddr>,
}

/// Records its address in `cancelled` if dropped while still armed.
struct DropProbe {
    address: SocketAddr,
    cancelled: Shared<SocketAddr>,
    armed: bool,
}

impl DropProbe {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DropProbe {
    fn drop(&mut self) {
        if self.armed {
            self.cancelled.lock().unwrap().push(self.address);
        }
    }
}

#[derive(Clone, Copy)]
enum Script {
    Hang,
    SucceedAfter(u64),
    FailAfter(u64),
}

type Attempt = std::pin::Pin<Box<dyn Future<Output = Result<SocketAddr>>>>;

/// A fake connector: each address follows its script, in virtual time.
fn connector(
    journal: &Journal,
    origin: tokio::time::Instant,
    script: impl Fn(SocketAddr) -> Script,
) -> impl FnMut(SocketAddr) -> Attempt {
    let journal = journal.clone();
    move |address| {
        journal
            .started
            .lock()
            .unwrap()
            .push((address, origin.elapsed()));
        let mut probe = DropProbe {
            address,
            cancelled: std::sync::Arc::clone(&journal.cancelled),
            armed: true,
        };
        let step = script(address);
        Box::pin(async move {
            let outcome = match step {
                Script::Hang => std::future::pending().await,
                Script::SucceedAfter(ms) => {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    Ok(address)
                }
                Script::FailAfter(ms) => {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                    Err(anyhow::anyhow!("no answer from {address}"))
                }
            };
            // A method, not a field write: a `move` block would capture the
            // `bool` field alone, by copy, and drop the probe at once.
            probe.disarm();
            outcome
        })
    }
}

fn expect_win(outcome: Result<Won<SocketAddr>, AllFailed>) -> Won<SocketAddr> {
    outcome.unwrap_or_else(|failed| panic!("{:#}", failed.into_error("gateway.example:51821")))
}

fn expect_failure(outcome: Result<Won<SocketAddr>, AllFailed>) -> AllFailed {
    match outcome {
        Ok(won) => panic!("nothing should win, {} did", won.address),
        Err(failed) => failed,
    }
}

/// The case the race exists for: IPv6 is published but broken on this
/// network. It never answers; IPv4 starts after the attempt delay and wins,
/// and the hung IPv6 attempt is cancelled rather than left running.
#[tokio::test(start_paused = true)]
async fn a_hung_ipv6_loses_to_ipv4_after_the_attempt_delay() {
    let journal = Journal::default();
    let origin = tokio::time::Instant::now();
    let won = expect_win(
        race(
            &addrs(&[V6, V4]),
            CONNECTION_ATTEMPT_DELAY,
            connector(&journal, origin, |address| {
                if address.is_ipv6() {
                    Script::Hang
                } else {
                    Script::SucceedAfter(20)
                }
            }),
        )
        .await,
    );

    assert_eq!(won.address, addr(V4));
    assert_eq!(won.value, addr(V4));
    assert_eq!(origin.elapsed(), Duration::from_millis(270));
    assert_eq!(
        *journal.started.lock().unwrap(),
        vec![
            (addr(V6), Duration::ZERO),
            (addr(V4), CONNECTION_ATTEMPT_DELAY)
        ]
    );
    assert_eq!(*journal.cancelled.lock().unwrap(), vec![addr(V6)]);
    assert_eq!(
        won.passed_over,
        vec![PassedOver {
            address: addr(V6),
            failure: None
        }]
    );
}

/// A healthy IPv6 answering inside the delay: IPv4 is never even started.
#[tokio::test(start_paused = true)]
async fn a_fast_ipv6_win_never_starts_ipv4() {
    let journal = Journal::default();
    let origin = tokio::time::Instant::now();
    let won = expect_win(
        race(
            &addrs(&[V6, V4]),
            CONNECTION_ATTEMPT_DELAY,
            connector(&journal, origin, |_| Script::SucceedAfter(30)),
        )
        .await,
    );

    assert_eq!(won.address, addr(V6));
    assert!(won.passed_over.is_empty());
    assert_eq!(
        *journal.started.lock().unwrap(),
        vec![(addr(V6), Duration::ZERO)]
    );
    assert!(journal.cancelled.lock().unwrap().is_empty());
}

/// A slow but working IPv6 that answers after IPv4 was started: IPv6 wins,
/// and the IPv4 attempt still in flight is cancelled.
#[tokio::test(start_paused = true)]
async fn a_slow_ipv6_win_cancels_the_started_ipv4() {
    let journal = Journal::default();
    let origin = tokio::time::Instant::now();
    let won = expect_win(
        race(
            &addrs(&[V6, V4]),
            CONNECTION_ATTEMPT_DELAY,
            connector(&journal, origin, |address| {
                if address.is_ipv6() {
                    Script::SucceedAfter(300)
                } else {
                    Script::Hang
                }
            }),
        )
        .await,
    );

    assert_eq!(won.address, addr(V6));
    assert_eq!(*journal.cancelled.lock().unwrap(), vec![addr(V4)]);
    assert_eq!(
        won.passed_over,
        vec![PassedOver {
            address: addr(V4),
            failure: None
        }]
    );
}

/// A failure does not wait out the delay: the next candidate starts at once.
#[tokio::test(start_paused = true)]
async fn a_failure_hands_over_without_waiting_for_the_delay() {
    let journal = Journal::default();
    let origin = tokio::time::Instant::now();
    let won = expect_win(
        race(
            &addrs(&[V6, V4]),
            CONNECTION_ATTEMPT_DELAY,
            connector(&journal, origin, |address| {
                if address.is_ipv6() {
                    Script::FailAfter(10)
                } else {
                    Script::SucceedAfter(10)
                }
            }),
        )
        .await,
    );

    assert_eq!(won.address, addr(V4));
    assert_eq!(origin.elapsed(), Duration::from_millis(20));
    assert_eq!(
        won.passed_over,
        vec![PassedOver {
            address: addr(V6),
            failure: Some(format!("no answer from {V6}")),
        }]
    );
}

/// Nothing answers: the error names the endpoint and every address tried,
/// each with its own cause.
#[tokio::test(start_paused = true)]
async fn every_candidate_failing_is_one_explicit_error() {
    let journal = Journal::default();
    let origin = tokio::time::Instant::now();
    let failed = expect_failure(
        race(
            &addrs(&[V6, V4]),
            CONNECTION_ATTEMPT_DELAY,
            connector(&journal, origin, |_| Script::FailAfter(1_000)),
        )
        .await,
    );
    assert_eq!(failed.failures.len(), 2);
    let message = format!("{:#}", failed.into_error("gateway.example:51821"));
    assert!(message.contains("gateway.example:51821"), "{message}");
    assert!(
        message.contains(&format!("{V6} (IPv6): no answer from {V6}")),
        "{message}"
    );
    assert!(
        message.contains(&format!("{V4} (IPv4): no answer from {V4}")),
        "{message}"
    );
}

/// One candidate — a literal endpoint — keeps the error it always had.
#[tokio::test(start_paused = true)]
async fn a_single_candidate_failure_is_returned_untouched() {
    let journal = Journal::default();
    let origin = tokio::time::Instant::now();
    let failed = expect_failure(
        race(
            &addrs(&[V4]),
            CONNECTION_ATTEMPT_DELAY,
            connector(&journal, origin, |_| Script::FailAfter(5)),
        )
        .await,
    );
    assert_eq!(
        format!("{:#}", failed.into_error("203.0.113.10:51821")),
        format!("no answer from {V4}")
    );
}

#[test]
fn a_clean_win_is_logged_as_information() {
    let selection = Selection {
        endpoint: "gateway.example:51821".into(),
        address: addr(V6),
        passed_over: Vec::new(),
    };
    assert_eq!(
        selection.describe(),
        (
            "info",
            format!("endpoint gateway.example:51821 : IPv6 {V6} retenu")
        )
    );
}

/// IPv6 gave nothing and IPv4 won: a warning naming both families.
#[test]
fn a_family_fallback_is_a_named_warning() {
    let selection = Selection {
        endpoint: "gateway.example:51821".into(),
        address: addr(V4),
        passed_over: vec![PassedOver {
            address: addr(V6),
            failure: None,
        }],
    };
    let (level, message) = selection.describe();
    assert_eq!(level, "warn");
    assert_eq!(
        message,
        format!(
            "endpoint gateway.example:51821 : IPv4 {V4} retenu après IPv6 {V6} sans réponse, \
             tentative annulée"
        )
    );
}
