use super::tests_support::*;
use super::*;

fn successor() -> RetainedCaTls {
    RetainedCaTls {
        private_key: "c3VjY2Vzc2V1cg==".into(),
        certificate_fingerprint: "b".repeat(64),
        counterpart_fingerprint: "a".repeat(64),
        activation_at: 5_000,
        not_after: 9_000,
    }
}

/// The successor is sealed **beside** the issuing key, not over it: the
/// gateway checks `ca_tls_epoch` with strict equality and only advances it
/// at `not_after`, so the authority keeps issuing under the outgoing
/// anchor for the whole overlap.
#[test]
fn staging_a_successor_leaves_the_issuing_key_where_it_was() {
    let mut vault = vault();
    let before = vault.open(&credential(1), &material(1)).expect("open");
    vault
        .stage_ca_tls_successor(&credential(1), &material(1), successor())
        .expect("stage");
    let after = vault.open(&credential(1), &material(1)).expect("open");
    assert_eq!(after.ca_tls_private_key, before.ca_tls_private_key);
    assert_eq!(after.retained_ca_tls, Some(successor()));
}

/// Two windows would leave three anchors alive, of which the domain's
/// registry names two.
#[test]
fn a_second_window_is_refused_while_one_is_open() {
    let mut vault = vault();
    vault
        .stage_ca_tls_successor(&credential(1), &material(1), successor())
        .expect("stage");
    let refused = vault.stage_ca_tls_successor(&credential(1), &material(1), successor());
    assert!(matches!(refused, Err(VaultError::CaTlsWindowOpen)));
}

/// `activation_at` is the fleet's second, not this vault's: at that point
/// the gateway accepts both anchors but still requires the outgoing
/// generation, so nothing here moves.
#[test]
fn nothing_moves_at_the_activation_second() {
    let mut vault = vault();
    vault
        .stage_ca_tls_successor(&credential(1), &material(1), successor())
        .expect("stage");
    let sealed = vault.sealed_payload.clone();
    let advance = vault
        .advance_ca_tls(&credential(1), &material(1), 5_000)
        .expect("advance");
    assert_eq!(advance, CaTlsAdvance::Awaiting { at: 9_000 });
    assert_eq!(vault.sealed_payload, sealed);
    let after = vault.open(&credential(1), &material(1)).expect("open");
    assert_eq!(after.retained_ca_tls, Some(successor()));
}

/// And nothing moves the second before the retirement either.
#[test]
fn nothing_moves_before_the_retirement_second() {
    let mut vault = vault();
    vault
        .stage_ca_tls_successor(&credential(1), &material(1), successor())
        .expect("stage");
    let sealed = vault.sealed_payload.clone();
    assert_eq!(
        vault
            .advance_ca_tls(&credential(1), &material(1), 8_999)
            .expect("advance"),
        CaTlsAdvance::Awaiting { at: 9_000 }
    );
    assert_eq!(vault.sealed_payload, sealed);
}

/// At `not_after`, one sealed write does both halves: the successor issues
/// and the outgoing private key ceases to exist. §9.2 permits the
/// destruction only here.
#[test]
fn the_window_closes_in_a_single_write_that_destroys_the_outgoing_key() {
    let mut vault = vault();
    let before = vault.open(&credential(1), &material(1)).expect("open");
    vault
        .stage_ca_tls_successor(&credential(1), &material(1), successor())
        .expect("stage");
    let advance = vault
        .advance_ca_tls(&credential(1), &material(1), 9_000)
        .expect("advance");
    assert_eq!(
        advance,
        CaTlsAdvance::Rotated {
            certificate_fingerprint: "b".repeat(64),
            destroyed_fingerprint: "a".repeat(64),
        }
    );
    let after = vault.open(&credential(1), &material(1)).expect("open");
    assert_eq!(after.ca_tls_private_key, successor().private_key);
    assert_ne!(after.ca_tls_private_key, before.ca_tls_private_key);
    assert_eq!(after.retained_ca_tls, None);
    assert_eq!(
        vault
            .advance_ca_tls(&credential(1), &material(1), 10_000)
            .expect("idle"),
        CaTlsAdvance::Idle
    );
}

/// A `CA-PQ` rotation must carry an open `CA-TLS` window through
/// untouched: it rotates the operator anchor, not the transport one.
#[test]
fn replacing_the_pq_anchor_may_not_drop_an_open_window() {
    let mut vault = vault();
    vault
        .stage_ca_tls_successor(&credential(1), &material(1), successor())
        .expect("stage");
    let dropped = AuthoritySecrets {
        ca_pq_private_key: "bmV3LXBx".into(),
        ca_pq_public_key: "bmV3LXBxLXB1Yg==".into(),
        ca_tls_private_key: "Y2EtdGxzLXByaXZhdGU=".into(),
        retained_ca_tls: None,
        retained_outgoing_ca_pq: None,
    };
    let refused = vault.replace_anchors(&credential(1), &material(1), &dropped);
    assert!(matches!(refused, Err(VaultError::Corrupt(_))));
    let carried = AuthoritySecrets {
        ca_pq_private_key: dropped.ca_pq_private_key.clone(),
        ca_pq_public_key: dropped.ca_pq_public_key.clone(),
        ca_tls_private_key: dropped.ca_tls_private_key.clone(),
        retained_ca_tls: Some(successor()),
        retained_outgoing_ca_pq: None,
    };
    vault
        .replace_anchors(&credential(1), &material(1), &carried)
        .expect("replace");
    let after = vault.open(&credential(1), &material(1)).expect("open");
    assert_eq!(after.retained_ca_tls, Some(successor()));
}

/// A window whose activation is not before its retirement is not a window.
#[test]
fn an_empty_window_is_refused() {
    let mut vault = vault();
    let empty = RetainedCaTls {
        activation_at: 9_000,
        ..successor()
    };
    let refused = vault.stage_ca_tls_successor(&credential(1), &material(1), empty);
    assert!(matches!(refused, Err(VaultError::Corrupt(_))));
}

/// The window is readable without the key it holds.
#[test]
fn the_open_window_is_readable_as_public_material() {
    let mut vault = vault();
    assert_eq!(
        vault
            .ca_tls_window(&credential(1), &material(1))
            .expect("w"),
        None
    );
    vault
        .stage_ca_tls_successor(&credential(1), &material(1), successor())
        .expect("stage");
    assert_eq!(
        vault
            .ca_tls_window(&credential(1), &material(1))
            .expect("w"),
        Some(("b".repeat(64), 9_000))
    );
}
