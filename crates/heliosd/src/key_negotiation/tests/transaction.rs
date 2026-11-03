//! PSK transactions: ownership, rollback, commit, release and reclamation.

use super::super::*;
use super::fixtures::*;

#[tokio::test]
async fn unconfirmed_transaction_restores_the_previous_slot() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([1; 16], &fixture),
        )
        .await
        .unwrap();
    handler.rollback([1; 16], CLIENT_KEY).await;

    let writes = plane.writes().await;
    assert_eq!(writes.len(), 2, "one candidate posed, one restore");
    assert!(
        writes[0].as_deref().is_some_and(|psk| psk != previous_psk),
        "preparation posts the freshly derived candidate"
    );
    assert_eq!(
        writes[1],
        Some(previous_psk),
        "rollback must put the peer's previous PSK back"
    );
}

#[tokio::test]
async fn undelivered_commit_restores_the_previous_slot() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([2; 16], &fixture),
        )
        .await
        .unwrap();
    // The client handshakes with the candidate PSK before confirming; the
    // gateway will refuse to sign without seeing it.
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, [2; 16], &fixture.client_private_key)
                .unwrap(),
        )
        .await
        .unwrap();
    // A rollback attempted after the commit must find nothing. This test
    // asserted the exact opposite in v4, where a commit that failed to
    // reach the client restored the previous slot — leaving that client
    // holding a valid, verifiable commit against a gateway that had undone
    // everything. Choosing one semantics is the whole point of v5's point
    // of no return.
    handler.rollback([2; 16], CLIENT_KEY).await;

    assert_eq!(
        plane.writes().await.len(),
        1,
        "nothing may touch the slot after the commit is signed"
    );
    let mut state = handler.transactions.lock().await;
    assert!(state.active.is_empty());
    let slot = state.slot(CLIENT_KEY);
    assert_eq!(
        slot.generation, 2,
        "two transitions are recorded: reserving the slot for the candidate, then committing \
             it. The reservation counts — it is what makes every actor holding the previous \
             generation a no-op from the moment the candidate is posed."
    );
    let SlotState::Committed(installed) = &slot.state else {
        panic!("a committed ml_kem negotiation must leave an owned slot");
    };
    assert_eq!(
        installed.transaction_id, [2; 16],
        "the receipt names the transaction a release will have to quote"
    );
}

#[tokio::test]
async fn certificate_mismatch_never_reaches_the_data_plane() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    assert!(matches!(
        handler
            .prepare("b".repeat(64), PUBLIC_SOURCE, request([3; 16], &fixture))
            .await,
        // Coarse on purpose: an unknown peer and a mismatched certificate
        // must be indistinguishable from the public boundary.
        Err(PublicError::Rejected)
    ));
    assert!(plane.writes().await.is_empty());
}

#[tokio::test]
async fn a_mode_below_the_peer_floor_is_refused() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    // `static_psk` under an `ml_kem` floor. This test used to present a
    // `classic` request; that mode is now refused at the decoder, one
    // layer earlier, which would have made the floor itself untested.
    assert!(matches!(
        handler
            .prepare(
                CERTIFICATE_FINGERPRINT.into(),
                PUBLIC_SOURCE,
                request_in_mode(
                    [4; 16],
                    &fixture,
                    ProtectionMode::StaticPsk,
                    Some(&previous_psk),
                ),
            )
            .await,
        // v4 answered `downgrade` here, which let anyone read a peer's
        // security floor off the public port.
        Err(PublicError::Rejected)
    ));
    assert!(plane.writes().await.is_empty());
}

#[test]
fn committed_modes_only_raise_the_persistent_floor() {
    let mut configured = network("static", &"a".repeat(64));
    assert_eq!(
        elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::MlKem).unwrap(),
        Some(ProtectionMode::StaticPsk)
    );
    assert_eq!(
        configured.peers[0].minimum_key_negotiation_mode,
        Some(ProtectionMode::MlKem)
    );
    assert_eq!(
        elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::StaticPsk).unwrap(),
        None
    );
    assert_eq!(
        configured.peers[0].minimum_key_negotiation_mode,
        Some(ProtectionMode::MlKem)
    );
}

#[test]
fn a_peer_without_a_floor_is_not_given_one_by_a_negotiation() {
    let mut configured = network("static", &"a".repeat(64));
    configured.peers[0].minimum_key_negotiation_mode = None;
    assert!(matches!(
        elevate_security_floor(&mut configured, CLIENT_KEY, ProtectionMode::MlKem),
        Err(PublicError::Rejected)
    ));
    assert_eq!(configured.peers[0].minimum_key_negotiation_mode, None);
}

#[tokio::test]
async fn a_confirmation_without_a_fresh_handshake_is_refused() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, _plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([9; 16], &fixture),
        )
        .await
        .unwrap();
    // Everything a stolen TLS + ML-DSA identity can produce, and nothing
    // more: the confirmation verifies, but the peer's WireGuard key was
    // never used, so the data plane reports no handshake.
    let refusal = handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, [9; 16], &fixture.client_private_key)
                .unwrap(),
        )
        .await;

    assert!(
        matches!(refusal, Err(PublicError::Rejected)),
        "a confirmation the data plane cannot corroborate must not be signed"
    );
}

#[tokio::test]
async fn a_committed_static_psk_is_configuration_not_an_owned_slot() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    // Floor already at `static_psk`, so the commit raises nothing: this
    // test is about what the slot holds, not about persisting a floor.
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::StaticPsk);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request_in_mode(
                [10; 16],
                &fixture,
                ProtectionMode::StaticPsk,
                Some(&previous_psk),
            ),
        )
        .await
        .unwrap();
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, [10; 16], &fixture.client_private_key)
                .unwrap(),
        )
        .await
        .unwrap();

    {
        let mut state = handler.transactions.lock().await;
        assert!(
            matches!(state.slot(CLIENT_KEY).state, SlotState::ConfiguredStatic),
            "a static PSK belongs to the configuration, not to the transaction"
        );
    }

    // A peer that has been silent for far longer than the reclamation
    // threshold. An ml_kem slot would be cleared; this one must not be,
    // because nothing would ever put the operator's value back.
    let ancient = helios_wireguard::PeerStatus {
        public_key: base64::engine::general_purpose::STANDARD
            .decode(CLIENT_KEY)
            .unwrap(),
        allowed_ips: vec!["100.64.1.2/32".into()],
        last_handshake: Some(
            std::time::SystemTime::now()
                - std::time::Duration::from_secs(
                    helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS * 10,
                ),
        ),
        endpoint: None,
        rx_bytes: 0,
        tx_bytes: 0,
    };
    assert!(
        handler.reclaimable(&[ancient]).await.is_empty(),
        "reclamation must never destroy a configured static PSK"
    );
}

#[tokio::test]
async fn a_stale_actor_cannot_clear_a_slot_that_moved_on() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([11; 16], &fixture),
        )
        .await
        .unwrap();
    let stale = handler
        .transactions
        .lock()
        .await
        .slot(CLIENT_KEY)
        .generation;
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, [11; 16], &fixture.client_private_key)
                .unwrap(),
        )
        .await
        .unwrap();

    let before = plane.writes().await.len();
    // A release or a reclamation decided from the pre-commit view. It must
    // not reach the data plane: the slot it saw no longer exists.
    handler.clear_slot(CLIENT_KEY, stale).await.unwrap();

    assert_eq!(
        plane.writes().await.len(),
        before,
        "an actor holding an old generation must not touch the data plane"
    );
    let mut state = handler.transactions.lock().await;
    assert!(matches!(
        state.slot(CLIENT_KEY).state,
        SlotState::Committed(_)
    ));
}

#[tokio::test]
async fn a_failed_clear_leaves_the_slot_owned_rather_than_orphaned() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request_in_mode([12; 16], &fixture, ProtectionMode::MlKem, None),
        )
        .await
        .unwrap();
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, [12; 16], &fixture.client_private_key)
                .unwrap(),
        )
        .await
        .unwrap();

    let generation = handler
        .transactions
        .lock()
        .await
        .slot(CLIENT_KEY)
        .generation;
    plane.start_failing().await;
    assert!(
        handler.clear_slot(CLIENT_KEY, generation).await.is_err(),
        "a data plane that refuses the write must be reported, not ignored"
    );

    // The record survives the failure. Dropping it first — the earlier
    // order — left the PSK posed with nothing pointing at it: a retried
    // release answered "released" without clearing anything, and
    // reclamation no longer knew the slot existed.
    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert_eq!(
        slot.generation, generation,
        "a failed write is not a transition"
    );
    assert!(
        matches!(slot.state, SlotState::Committed(_)),
        "the slot must stay owned so the next attempt can still clear it"
    );
}

/// The interleaving the generation was introduced for, but which reading
/// it without taking it never stopped.
///
/// A peer whose handshake has aged past the reclamation threshold
/// renegotiates. The reclaimer's ten-second snapshot still shows the old,
/// stale handshake, and the slot record still described the *displaced*
/// PSK — so the reclamation matched the current generation, cleared the
/// data plane, and wiped a candidate that was about to commit. Naming the
/// slot `preparing` from the moment it is reserved is what removes the
/// match.
#[tokio::test]
async fn a_candidate_being_prepared_is_not_reclaimable() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([20; 16], &fixture),
        )
        .await
        .unwrap();

    let ancient = helios_wireguard::PeerStatus {
        public_key: base64::engine::general_purpose::STANDARD
            .decode(CLIENT_KEY)
            .unwrap(),
        endpoint: None,
        last_handshake: Some(
            std::time::SystemTime::now()
                - std::time::Duration::from_secs(
                    helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS * 10,
                ),
        ),
        allowed_ips: Vec::new(),
        rx_bytes: 0,
        tx_bytes: 0,
    };
    assert!(
        handler.reclaimable(&[ancient]).await.is_empty(),
        "a slot a transaction is preparing has an owner and a deadline of its own; the \
             reclaimer must leave it to them"
    );

    // And the candidate is still the only thing the data plane was told.
    assert_eq!(plane.writes().await.len(), 1);
}

fn handshake_aged(secs: u64) -> helios_wireguard::PeerStatus {
    helios_wireguard::PeerStatus {
        public_key: base64::engine::general_purpose::STANDARD
            .decode(CLIENT_KEY)
            .unwrap(),
        endpoint: None,
        last_handshake: Some(std::time::SystemTime::now() - std::time::Duration::from_secs(secs)),
        allowed_ips: Vec::new(),
        rx_bytes: 0,
        tx_bytes: 0,
    }
}

/// The field incident: Orion reconnects after an hour away and renews
/// twice within seconds.
///
/// The reclaimer's snapshot predates both commits and still carries the
/// handshake of the previous session. The generation it reads is the
/// current one, so nothing downstream stops it: the slot was cleared three
/// seconds after a commit that had just proved a fresh handshake, the
/// tunnel fell, and the next renewal was refused for want of a committed
/// slot. A handshake older than the slot says nothing about the slot.
#[tokio::test]
async fn a_handshake_older_than_the_slot_does_not_reclaim_it() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    commit(&handler, &plane, &fixture, [21; 16], PUBLIC_SOURCE).await;
    commit(&handler, &plane, &fixture, [22; 16], TUNNEL_SOURCE).await;

    let previous_session = handshake_aged(helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS * 16);
    assert!(
        handler.reclaimable(&[previous_session]).await.is_empty(),
        "a slot committed seconds ago cannot have gone without a handshake for longer"
    );
}

#[tokio::test]
async fn a_slot_without_a_handshake_since_its_commit_is_reclaimed() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    commit(&handler, &plane, &fixture, [23; 16], PUBLIC_SOURCE).await;
    let threshold = std::time::Duration::from_secs(helios_wireguard::PSK_RECLAIM_AFTER_STALE_SECS);
    {
        let mut state = handler.transactions.lock().await;
        let SlotState::Committed(installed) = &mut state.slot(CLIENT_KEY).state else {
            panic!("the commit must leave an owned slot");
        };
        installed.installed_at -= threshold;
    }

    let reclaimed = handler
        .reclaimable(&[handshake_aged(threshold.as_secs() * 16)])
        .await;
    assert_eq!(
        reclaimed.len(),
        1,
        "silent since its commit: the peer is gone"
    );
    assert!(
        reclaimed[0].2.contains("no WireGuard handshake"),
        "the journal names the cause: {reclaimed:?}"
    );
}

/// The other stale actor: a `release` naming the PSK the candidate
/// displaced.
///
/// It authenticates, it names a transaction the gateway really did commit,
/// and it arrives while the next negotiation is in flight. Honouring it
/// clears the data plane under a candidate whose handshake proof may
/// already be in — leaving the gateway free to sign a commit for a PSK it
/// no longer holds.
#[tokio::test]
async fn a_release_naming_the_displaced_psk_cannot_wipe_the_candidate() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    // First negotiation, committed: it owns the slot.
    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([21; 16], &fixture),
        )
        .await
        .unwrap();
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, [21; 16], &fixture.client_private_key)
                .unwrap(),
        )
        .await
        .unwrap();

    // Second negotiation, in flight: its candidate is on the data plane.
    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([22; 16], &fixture),
        )
        .await
        .unwrap();
    let candidate = plane.writes().await.last().cloned().flatten();
    let generation = handler
        .transactions
        .lock()
        .await
        .slot(CLIENT_KEY)
        .generation;

    // The delayed release for the first transaction lands now.
    handler.clear_slot(CLIENT_KEY, generation).await.unwrap();

    assert_eq!(
        plane.writes().await.last().cloned().flatten(),
        candidate,
        "the candidate must still be the last thing the data plane was told"
    );
    let mut state = handler.transactions.lock().await;
    assert!(
        matches!(
            state.slot(CLIENT_KEY).state,
            SlotState::Preparing { transaction_id, .. } if transaction_id == [22; 16]
        ),
        "the slot belongs to the transaction preparing it, not to the one it displaced"
    );
}

/// A `prepare` destroyed after it posed its candidate and before it
/// recorded anything.
///
/// This is what the absolute connection deadline used to do — it dropped
/// the future, and dropping a future runs nothing. The undo therefore
/// cannot depend on the transaction record: it is driven off the slot,
/// which names its own owner.
#[tokio::test]
async fn a_transaction_that_was_never_recorded_is_still_undone() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([23; 16], &fixture),
        )
        .await
        .unwrap();
    // Exactly what a cancellation between `install` and the insert leaves
    // behind: a posed candidate and no record of it.
    handler.transactions.lock().await.active.remove(&[23; 16]);

    handler.rollback([23; 16], CLIENT_KEY).await;

    assert_eq!(
        plane.writes().await.last().cloned().flatten(),
        Some(previous_psk),
        "the displaced PSK must come back even with no transaction to read it from"
    );
    let mut state = handler.transactions.lock().await;
    assert!(
        !state.peers.contains(CLIENT_KEY),
        "the reservation must go too, or that peer never negotiates again"
    );
    let slot = state.slot(CLIENT_KEY);
    assert!(matches!(
        slot.state,
        SlotState::ConfiguredStatic | SlotState::Empty
    ));
    // The rest period is owed by the *slot*, not by the transaction
    // record. A destroyed preparation may not have inserted that record
    // yet, so the slot is the only reliable witness that a backend write
    // was attempted and that §11.3 therefore requires a rest.
    assert!(
        slot.resting_until.is_some(),
        "a candidate that reached the data plane rests the peer, whatever is left of its \
             transaction record"
    );
}

/// §11.1, priority 2: a `release` arriving during `preparing` is a no-op.
///
/// Only a `committed` state whose owner the release names exactly is
/// withdrawn. A candidate belongs to the connection preparing it, and that
/// connection already has an exit path for every way it can end — its
/// rollback guard, which survives even the destruction of its task.
/// Letting a second message cancel a candidate gave one slot two writers
/// with no ordering between them; the client sends no release before its
/// own commit, so the only callers left would be stale or forged.
#[tokio::test]
async fn a_release_arriving_during_preparation_touches_nothing() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([26; 16], &fixture),
        )
        .await
        .unwrap();
    let candidate = plane.writes().await.last().cloned().flatten();

    release_in_tunnel(&handler, &fixture, [26; 16])
        .await
        .unwrap();

    assert_eq!(
        plane.writes().await.last().cloned().flatten(),
        candidate,
        "the candidate must still be the last thing the data plane was told"
    );

    // And the connection that posed it can still confirm: nothing took
    // its slot away.
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, [26; 16], &fixture.client_private_key)
                .unwrap(),
        )
        .await
        .expect("a no-op release must not cost the transaction its commit");
}

/// A connection may be cancelled while `prepare` is still deriving
/// material, before the candidate reaches the backend.
///
/// Cancelling the slot is not enough by itself: the suspended preparation
/// must re-check ownership immediately before its write, otherwise it
/// resumes after rollback and installs a candidate for a transaction that
/// no longer exists.
#[tokio::test]
async fn a_rolled_back_preparation_cannot_install_its_candidate_late() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let candidate = base64::engine::general_purpose::STANDARD.encode([8u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let transaction_id = [27; 16];
    let generation = {
        let mut state = handler.transactions.lock().await;
        state.peers.insert(CLIENT_KEY.into());
        let slot = state.slot(CLIENT_KEY);
        slot.generation += 1;
        slot.state = SlotState::Preparing {
            transaction_id,
            previous: Box::new(SlotState::Empty),
            address: "100.64.1.2/32".into(),
            previous_psk: Some(SecretString::new(&previous_psk)),
            install_attempted: false,
        };
        slot.generation
    };

    // The rollback wins while the original preparation is suspended.
    handler.abandon(transaction_id, CLIENT_KEY).await;
    let writes_after_rollback = plane.writes().await.len();

    let result = handler
        .install_candidate(
            transaction_id,
            CLIENT_KEY,
            generation,
            Some(SecretString::new(candidate)),
            None,
            Transaction {
                public_key: CLIENT_KEY.into(),
                address: "100.64.1.2/32".into(),
                client_pq_public_key: fixture.client_certificate.ml_dsa_87_public_key.clone(),
                mode: ProtectionMode::MlKem,
                server_challenge: TEST_CHALLENGE,
                generation,
                handshake_before_install: None,
            },
        )
        .await;

    assert!(matches!(result, Err(PublicError::Rejected)));
    assert_eq!(
        plane.writes().await.len(),
        writes_after_rollback,
        "a preparation that lost its slot must never reach the backend"
    );
    assert!(
        !handler
            .transactions
            .lock()
            .await
            .active
            .contains_key(&transaction_id),
        "a cancelled preparation must not recreate its transaction record"
    );
}

/// If confirmation wins before the release is serialized, the release
/// must act on the now-committed owner rather than on an obsolete snapshot
/// that still called it a candidate.
#[tokio::test]
async fn a_release_after_commit_clears_the_same_transaction() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    let transaction_id = [28; 16];

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request(transaction_id, &fixture),
        )
        .await
        .unwrap();
    plane.handshake_happens().await;
    handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, transaction_id, &fixture.client_private_key)
                .unwrap(),
        )
        .await
        .unwrap();

    release_in_tunnel(&handler, &fixture, transaction_id)
        .await
        .unwrap();

    assert_eq!(
        plane.writes().await.last().cloned().flatten(),
        None,
        "a release serialized after commit must clear that committed PSK"
    );
    let mut state = handler.transactions.lock().await;
    assert!(matches!(state.slot(CLIENT_KEY).state, SlotState::Empty));
}

/// §4.5: a rollback that had already posed a candidate rests the peer.
///
/// A stolen negotiation identity without the peer's WireGuard key can
/// never commit, but nothing stopped it posing and rolling back a
/// candidate as fast as the round-trip allowed — which keeps a working
/// slot in permanent oscillation.
#[tokio::test]
async fn a_rolled_back_candidate_rests_the_peer() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, _plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([24; 16], &fixture),
        )
        .await
        .unwrap();
    handler.rollback([24; 16], CLIENT_KEY).await;

    let refusal = handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([25; 16], &fixture),
        )
        .await;
    assert!(
        matches!(refusal, Err(PublicError::Rejected)),
        "the next attempt waits out the rest period"
    );
    assert!(
        !handler.transactions.lock().await.peers.contains(CLIENT_KEY),
        "a refusal during the rest period must not leave the peer reserved"
    );
}

/// Removes the test peer from admission, as a reload of `network.toml` does.
async fn remove_from_admission(handler: &GatewayHandler) {
    handler
        .network
        .write()
        .await
        .peers
        .retain(|peer| peer.public_key != CLIENT_KEY);
}

/// §11.1 priority 1: no rollback decided before the removal recreates the
/// peer's previous PSK.
///
/// The candidate is posed, then the operator removes the peer. Its
/// connection's rollback guard fires afterwards, as it does on any timeout:
/// without the revocation it would put the displaced PSK back on the data
/// plane for a peer nobody admits any more.
#[tokio::test]
async fn a_rollback_after_removal_restores_nothing() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([40; 16], &fixture),
        )
        .await
        .unwrap();
    let reserved = handler
        .transactions
        .lock()
        .await
        .slot(CLIENT_KEY)
        .generation;
    remove_from_admission(&handler).await;
    handler.rollback([40; 16], CLIENT_KEY).await;

    assert_eq!(
        plane.writes().await.len(),
        1,
        "only the candidate reached the data plane; the rollback must not restore anything"
    );
    let mut state = handler.transactions.lock().await;
    assert!(state.active.is_empty() && !state.peers.contains(CLIENT_KEY));
    let slot = state.slot(CLIENT_KEY);
    assert!(matches!(slot.state, SlotState::Revoked));
    assert!(slot.generation > reserved);
}

/// A removal between the handshake proof and the signature ends without a
/// commit: the gateway must not sign for a peer it no longer admits.
#[tokio::test]
async fn a_removed_peer_is_not_committed() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);

    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([41; 16], &fixture),
        )
        .await
        .unwrap();
    plane.handshake_happens().await;
    remove_from_admission(&handler).await;

    assert!(handler
        .confirm(
            authenticate_confirmation(TEST_CHALLENGE, [41; 16], &fixture.client_private_key)
                .unwrap(),
        )
        .await
        .is_err());
    let mut state = handler.transactions.lock().await;
    assert!(matches!(state.slot(CLIENT_KEY).state, SlotState::Revoked));
}

/// The sweep revokes a slot no actor touches, and drops the static PSK
/// baseline with it; a `release` naming the old transaction is then a no-op.
#[tokio::test]
async fn the_sweep_revokes_a_committed_slot_and_its_static_baseline() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    commit(&handler, &plane, &fixture, [42; 16], PUBLIC_SOURCE).await;
    remove_from_admission(&handler).await;

    handler.revoke_unadmitted().await;

    assert!(matches!(
        handler.transactions.lock().await.slot(CLIENT_KEY).state,
        SlotState::Revoked
    ));
    assert!(
        !handler.static_psks.read().await.contains_key(CLIENT_KEY),
        "a removed peer's static PSK must not slide back onto its key at re-admission"
    );
    let writes = plane.writes().await.len();
    let _ = release_in_tunnel(&handler, &fixture, [42; 16]).await;
    assert_eq!(plane.writes().await.len(), writes);
}

/// Revocation is terminal until the key is admitted again, and a new
/// admission starts from an empty slot rather than from what the removed
/// peer held.
#[tokio::test]
async fn a_readmitted_peer_negotiates_from_an_empty_slot() {
    let previous_psk = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
    let fixture = pq_fixture();
    let (handler, plane) = gateway_with(&fixture, &previous_psk, ProtectionMode::MlKem);
    commit(&handler, &plane, &fixture, [43; 16], PUBLIC_SOURCE).await;
    let readmitted = handler.network.read().await.duplicate();
    remove_from_admission(&handler).await;
    handler.revoke_unadmitted().await;
    let revoked = handler
        .transactions
        .lock()
        .await
        .slot(CLIENT_KEY)
        .generation;

    *handler.network.write().await = readmitted;
    handler
        .prepare(
            CERTIFICATE_FINGERPRINT.into(),
            PUBLIC_SOURCE,
            request([44; 16], &fixture),
        )
        .await
        .expect("a re-admitted peer negotiates again");

    let mut state = handler.transactions.lock().await;
    let slot = state.slot(CLIENT_KEY);
    assert!(slot.generation > revoked);
    assert!(matches!(
        &slot.state,
        SlotState::Preparing { previous, .. } if matches!(**previous, SlotState::Empty)
    ));
}
