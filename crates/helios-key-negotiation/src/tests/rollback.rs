use std::{
    sync::{atomic::Ordering, Arc},
    time::Duration,
};

use aether::key_negotiation::{authenticate_request, KEY_NEGOTIATION_NONCE_LEN};

use super::fixtures::{bench, simple_request, test_pki, Handler, CLIENT_WG_KEY, GATEWAY_WG_KEY};
use crate::{negotiate, request_challenge, server::NegotiationHandler, transaction::RollbackGuard};

/// The rollback survives the destruction of the task that owned it.
///
/// This is what the absolute-lifetime timeout does to a connection still
/// waiting for its confirmation: it drops the future, and dropping a
/// future runs none of the exit paths. Before the guard existed that left
/// the candidate PSK posed and the peer reserved, with nothing left able
/// to resolve either — one unfinished connection locked an admitted peer
/// out until the daemon restarted.
#[tokio::test]
async fn a_destroyed_connection_still_rolls_its_candidate_back() {
    let pki = test_pki();
    let handler = Arc::new(Handler::new(&pki));
    drop(RollbackGuard::arm(
        Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
        [3; 16],
        CLIENT_WG_KEY.into(),
    ));

    // `Drop` cannot await, so it spawns; yielding is what lets that run.
    tokio::task::yield_now().await;

    assert!(
        handler.rolled_back.load(Ordering::SeqCst),
        "a candidate must be undone even when nothing returns from the connection"
    );
}

#[tokio::test]
async fn a_disarmed_guard_never_undoes_a_signed_commit() {
    let pki = test_pki();
    let handler = Arc::new(Handler::new(&pki));
    let mut guard = RollbackGuard::arm(
        Arc::clone(&handler) as Arc<dyn NegotiationHandler>,
        [3; 16],
        CLIENT_WG_KEY.into(),
    );
    guard.disarm();
    drop(guard);

    tokio::task::yield_now().await;

    assert!(
        !handler.rolled_back.load(Ordering::SeqCst),
        "past the point of no return there is nothing to undo, and undoing it would hand a \
         client a valid commit against a gateway that had restored the previous state"
    );
}

/// A rollback destroyed **inside its own await** must be run again.
///
/// The guard used to clear `armed` before awaiting the rollback, which
/// reintroduced the hole it exists to close: the ceiling fires while the
/// rollback is writing to the data plane, the task is destroyed, and
/// `Drop` finds a guard that has already declared itself finished. The
/// candidate stays posed and the peer stays reserved — and on the gateway
/// side that window is real, because undoing removes the transaction
/// record *before* it awaits the restore.
#[tokio::test]
async fn a_rollback_destroyed_inside_its_own_await_is_run_again() {
    let pki = test_pki();
    let handler = Arc::new(Handler::with_blocked_rollback(&pki));

    let task = tokio::spawn({
        let handler = Arc::clone(&handler) as Arc<dyn NegotiationHandler>;
        async move {
            let mut guard = RollbackGuard::arm(handler, [4; 16], CLIENT_WG_KEY.into());
            guard.roll_back().await;
        }
    });
    // Let it reach the suspension point inside `rollback`, then destroy
    // it there — which is exactly what the absolute ceiling does.
    tokio::task::yield_now().await;
    task.abort();
    let _ = task.await;
    assert_eq!(
        handler.rollbacks.load(std::sync::atomic::Ordering::SeqCst),
        0,
        "the first attempt must not have completed, or this proves nothing"
    );

    handler.rollback_gate.add_permits(1);
    tokio::time::timeout(Duration::from_secs(5), async {
        while handler.rollbacks.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("a rollback destroyed part-way through must be retried by the guard");
}

/// No phase may outlive the connection that carries it.
///
/// The 45-second confirmation wait is the one that would: a client that
/// dawdles before requesting leaves less than 45 seconds of budget, and
/// the ceiling would then fire during the wait — destroying the task
/// instead of timing the phase out. Clamping keeps the exit on an
/// ordinary code path.
/// Une session abandonnée avant confirmation doit être défaite : c'est le
/// rollback, qui n'existe que **avant** la signature du commit.
#[tokio::test]
async fn closing_an_unconfirmed_session_requests_rollback() {
    let pki = test_pki();
    let (handler, task, client, server_addr) = bench(&pki);

    let pending = request_challenge(&client, server_addr, "localhost", GATEWAY_WG_KEY)
        .await
        .unwrap();
    let mut request = simple_request([4; KEY_NEGOTIATION_NONCE_LEN]);
    request.server_challenge = pending.server_challenge();
    request.server_name = "localhost".into();
    let authenticated_request = authenticate_request(
        request,
        pki.client_pq_certificate.clone(),
        &pki.client_pq_private_key,
    )
    .unwrap();
    let (_, session) = negotiate(&client, pending, &authenticated_request)
        .await
        .unwrap();
    drop(session);

    tokio::time::timeout(Duration::from_secs(5), async {
        while !handler.rolled_back.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(!handler.confirmed.load(Ordering::SeqCst));
    client.close(0u32.into(), b"test complete");
    task.abort();
}
