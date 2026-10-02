//! The negotiation listener on both address families, through one socket.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use super::fixtures::{test_pki, Handler, GATEWAY_WG_KEY};
use crate::{
    client_endpoint, dual_stack_server_endpoint, request_challenge, serve, server::source_bucket,
    ListenFamilies, NegotiationHandler, TransportError,
};

/// Why this host cannot exercise IPv6 loopback, if it cannot.
///
/// WSL2 and some CI containers run without IPv6. A test that needs `[::1]`
/// then says so on stderr and returns: it must never pass as if it had
/// proven anything.
fn ipv6_loopback_unavailable() -> Option<std::io::Error> {
    std::net::UdpSocket::bind("[::1]:0").err()
}

/// The per-source budget is decided on what the socket reports, and a
/// dual-stack socket reports an IPv4 client as `::ffff:a.b.c.d`. Read as
/// IPv6, that address sits in `::/64` with every other IPv4 client on the
/// Internet, and one of them could spend the budget of all the others.
///
/// A real IPv4 client against the real listener, so the address checked is
/// the one quinn actually hands to `serve` — not a literal the test chose.
#[tokio::test]
async fn an_ipv4_client_on_the_dual_stack_listener_is_budgeted_as_its_ipv4_address() {
    let pki = test_pki();
    let (server, families) =
        dual_stack_server_endpoint(0, &pki.server, std::slice::from_ref(&pki.ca_der)).unwrap();
    if let ListenFamilies::Ipv4Only { reason } = &families {
        eprintln!(
            "SKIPPED: the listener could not open IPv6 here ({reason}); no mapped source to check"
        );
        return;
    }
    let port = server.local_addr().unwrap().port();
    let client = client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &pki.client,
        pki.ca_der.clone(),
    )
    .unwrap();
    let connecting = client
        .connect(SocketAddr::from((Ipv4Addr::LOCALHOST, port)), "localhost")
        .unwrap();
    let handshake = tokio::spawn(async move {
        let _ = connecting.await;
    });

    let incoming = tokio::time::timeout(Duration::from_secs(5), server.accept())
        .await
        .expect("the IPv4 client reaches the dual-stack listener")
        .expect("the listener is open");
    let reported = incoming.remote_address();
    assert_eq!(
        reported.ip(),
        "::ffff:127.0.0.1".parse::<IpAddr>().unwrap(),
        "a dual-stack socket reports an IPv4 client in its mapped form"
    );
    assert_eq!(
        source_bucket(reported),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "the IPv4 client is charged to its own address, not to `::/64`"
    );

    incoming.refuse();
    handshake.abort();
    client.close(0u32.into(), b"test complete");
}

/// One listener, both families, through the whole public path — Retry
/// included, whose token is bound to the address in the socket's own form.
#[tokio::test]
async fn both_families_reach_a_challenge_on_one_dual_stack_listener() {
    let pki = test_pki();
    let (server, families) =
        dual_stack_server_endpoint(0, &pki.server, std::slice::from_ref(&pki.ca_der)).unwrap();
    let port = server.local_addr().unwrap().port();
    let handler = Arc::new(Handler::new(&pki));
    let task = tokio::spawn(serve(
        server,
        Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
    ));

    let v4_client = client_endpoint(
        "127.0.0.1:0".parse().unwrap(),
        &pki.client,
        pki.ca_der.clone(),
    )
    .unwrap();
    let pending = request_challenge(
        &v4_client,
        SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        "localhost",
        GATEWAY_WG_KEY,
    )
    .await
    .expect("an IPv4 client still negotiates on the dual-stack listener");
    drop(pending);
    v4_client.close(0u32.into(), b"test complete");

    match (&families, ipv6_loopback_unavailable()) {
        (ListenFamilies::Ipv4Only { reason }, _) => {
            eprintln!("SKIPPED (IPv6 half): the listener serves IPv4 only here ({reason})");
        }
        (ListenFamilies::DualStack, Some(error)) => {
            eprintln!("SKIPPED (IPv6 half): [::1] cannot be bound on this host ({error})");
        }
        (ListenFamilies::DualStack, None) => {
            let v6_client =
                client_endpoint("[::1]:0".parse().unwrap(), &pki.client, pki.ca_der.clone())
                    .unwrap();
            let pending = request_challenge(
                &v6_client,
                format!("[::1]:{port}").parse().unwrap(),
                "localhost",
                GATEWAY_WG_KEY,
            )
            .await
            .expect("an IPv6 client negotiates on the same listener");
            drop(pending);
            v6_client.close(0u32.into(), b"test complete");
        }
    }
    task.abort();
}

/// A host without IPv6 must keep its IPv4 negotiation: the kernel refusing
/// the address family is a missing capability, and the listener says so
/// instead of failing.
#[cfg(unix)]
#[test]
fn an_unsupported_ipv6_family_falls_back_to_ipv4_only() {
    let families = ListenFamilies::after_dual_stack_error(std::io::Error::from_raw_os_error(
        libc::EAFNOSUPPORT,
    ))
    .expect("a missing IPv6 family degrades to IPv4");
    let ListenFamilies::Ipv4Only { reason } = &families else {
        panic!("expected an IPv4-only listener, got {families:?}");
    };
    assert!(
        reason.contains(&std::io::Error::from_raw_os_error(libc::EAFNOSUPPORT).to_string()),
        "the reason names the operating system's answer: {reason}"
    );
    assert!(families.to_string().starts_with("IPv4 only"));
}

/// Every other failure is the failure it was before IPv6. A port in use
/// that quietly became an IPv4 listener would hide the real fault behind a
/// degraded service — or, worse, bind beside whatever already holds it.
#[cfg(unix)]
#[test]
fn any_other_socket_error_still_fails_the_listener() {
    for errno in [
        libc::EADDRINUSE,
        libc::EACCES,
        libc::EADDRNOTAVAIL,
        libc::EINVAL,
    ] {
        let error =
            ListenFamilies::after_dual_stack_error(std::io::Error::from_raw_os_error(errno))
                .expect_err("only EAFNOSUPPORT degrades");
        assert_eq!(
            error.raw_os_error(),
            Some(errno),
            "the error comes back unchanged"
        );
    }
    assert!(ListenFamilies::after_dual_stack_error(std::io::Error::other("opaque")).is_err());
}

/// The same rule on a real socket: a port someone else holds fails the
/// listener rather than sending it to the IPv4 fallback.
#[tokio::test]
async fn a_port_already_in_use_fails_the_dual_stack_listener() {
    let pki = test_pki();
    let holder = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let port = holder.local_addr().unwrap().port();
    match dual_stack_server_endpoint(port, &pki.server, std::slice::from_ref(&pki.ca_der)) {
        Err(TransportError::Io(error)) => {
            assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse, "{error}");
        }
        Err(other) => panic!("expected the bind error, got {other:?}"),
        Ok((_, families)) => panic!("a held port must not yield a listener ({families})"),
    }
}
