//! The revocation's cut, against a gateway and an Astra that answer as the test says.
//!
//! The gateway's admission and the tunnel are simulated; the relay beside the vault is
//! read from disk. The cut is what these tests reach: nothing here asks a key, so no
//! campaign is opened and no vault is opened.

use std::cell::Cell;
use std::path::PathBuf;
use std::sync::mpsc::channel;

use aether::certificates::encoding::{Id16, WireGuardKey};
use aether::certificates::operator_session::{GestureState, OperatorStatus, Refusal};
use aether::wg::generate_keypair;
use astra_operator::operations::revocation::RevocationReasonChoice;
use astra_operator::tunnel::Tunnel;
use orion_core::gateway_admin::{AdmittedPeer, GatewayAdminError};

use super::super::Press;
use super::{run_with, Reach};
use crate::operator::{GatewayTarget, RevocationGesture};

/// Nothing answers at this address: a tunnel to it reaches no Astra.
const NO_ONE_ANSWERS: &str = "http://127.0.0.1:1";

/// A domain's directory of its own, with its relay naming `gateway_key`.
struct Domain {
    directory: PathBuf,
    vault_path: PathBuf,
    gateway_key: WireGuardKey,
}

impl Domain {
    fn new(label: &str) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "orion-revocation-{label}-{}-{}",
            std::process::id(),
            crate::operator::now_unix()
        ));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("directory");
        let gateway_key = WireGuardKey::from_bytes([0x61; 32]);
        let vault_path = directory.join("astra").join("authority-vault.json");
        let relay = astra_operator::handoff::DomainHandoff {
            trust_domain_id: "domain".into(),
            rp_id: "astra.example".into(),
            ca_pq_public_key: "ca".into(),
            vault_fingerprint: "vault".into(),
            ca_epoch: None,
            ca_tls_epoch: None,
            ca_tls_certificate: None,
            gateway_wg_public_key: Some(gateway_key.to_base64()),
            server_name: None,
            astra_service_public_key: None,
            astra_service_key_epoch: None,
            astra_authority_url: None,
        };
        astra_operator::handoff::save(&astra_operator::handoff::path_beside(&vault_path), &relay)
            .expect("relay");
        Self {
            directory,
            vault_path,
            gateway_key,
        }
    }

    /// The gateway the domain's relay names, as the tunnel leads to it.
    fn target(&self, own_key: Option<WireGuardKey>) -> GatewayTarget {
        GatewayTarget {
            address: NO_ONE_ANSWERS.into(),
            peer_key: self.gateway_key.to_base64(),
            own_key: own_key.map(|key| key.to_base64()),
        }
    }
}

impl Drop for Domain {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

/// The workstation the gesture cuts, and the key it is admitted under.
fn workstation() -> (WireGuardKey, String) {
    let key = WireGuardKey::parse(&generate_keypair().expect("workstation key").public_key)
        .expect("a WireGuard key");
    (key, "poste-1".to_string())
}

fn revoke(peer: &WireGuardKey, name: &str) -> RevocationGesture {
    RevocationGesture::Revoke {
        peer: peer.to_base64(),
        name: name.to_string(),
        reason: RevocationReasonChoice::StolenOrLost,
    }
}

/// What the test's gateway answers, and how often it was asked to cut.
struct Gateway {
    admitted: Vec<AdmittedPeer>,
    reads: Cell<usize>,
    cuts: Cell<usize>,
}

impl Gateway {
    fn admitting(name: &str, key: &WireGuardKey) -> Self {
        Self {
            admitted: vec![AdmittedPeer {
                name: name.to_string(),
                wg_public_key: key.to_base64(),
            }],
            reads: Cell::new(0),
            cuts: Cell::new(0),
        }
    }

    fn read(&self, _base: &str) -> Result<Vec<AdmittedPeer>, GatewayAdminError> {
        self.reads.set(self.reads.get() + 1);
        Ok(self.admitted.clone())
    }

    fn withdraw(&self, _base: &str, _name: &str) -> Result<(), GatewayAdminError> {
        self.cuts.set(self.cuts.get() + 1);
        Ok(())
    }
}

/// Runs a gesture against the gateway and the tunnel the test gives, and returns what it
/// returned and every status it published. No press is sent: nothing here asks a key.
fn drive(
    domain: &Domain,
    gesture: RevocationGesture,
    target: &GatewayTarget,
    gateway: &Gateway,
    remote: &Tunnel,
) -> (Result<(), String>, Vec<OperatorStatus>) {
    let (_keep_open, presses) = channel::<Press>();
    let mut published = Vec::new();
    let reach = Reach {
        remote,
        admitted: &|base: &str| gateway.read(base),
        withdraw: &|base: &str, name: &str| gateway.withdraw(base, name),
        connect: &|_: isize| Err((Refusal::KeyDeclined, "no key in this test".into())),
        now: &|| 1_800_000_000,
    };
    let outcome = run_with(
        Id16::new([9; 16]).expect("session"),
        gesture,
        target,
        presses,
        &mut |status| published.push(status),
        &domain.vault_path,
        &reach,
    );
    (outcome, published)
}

fn last_refusal(published: &[OperatorStatus]) -> Option<Refusal> {
    published.last().and_then(|status| status.refusal)
}

/// A name the gateway binds to another key is never cut, whatever the operator chose.
#[test]
fn cut_refuses_a_name_bound_to_another_key() {
    let domain = Domain::new("name");
    let (peer, name) = workstation();
    let (other, _) = workstation();
    let gateway = Gateway::admitting(&name, &other);
    let target = domain.target(None);
    let (outcome, published) = drive(
        &domain,
        revoke(&peer, &name),
        &target,
        &gateway,
        &Tunnel::new(NO_ONE_ANSWERS).expect("tunnel"),
    );

    assert!(outcome.is_err());
    assert_eq!(gateway.cuts.get(), 0, "nothing is cut");
    assert_eq!(last_refusal(&published), Some(Refusal::PeerNameMismatch));
}

/// This workstation is never cut: its own console would go with it.
#[test]
fn this_workstation_is_never_cut() {
    let domain = Domain::new("self");
    let (peer, name) = workstation();
    let gateway = Gateway::admitting(&name, &peer);
    let target = domain.target(Some(peer));
    let (outcome, published) = drive(
        &domain,
        revoke(&peer, &name),
        &target,
        &gateway,
        &Tunnel::new(NO_ONE_ANSWERS).expect("tunnel"),
    );

    assert!(outcome.is_err());
    assert_eq!(gateway.reads.get(), 0, "the admission is not even read");
    assert_eq!(gateway.cuts.get(), 0, "nothing is cut");
    assert_eq!(last_refusal(&published), Some(Refusal::SelfRevocation));
}

/// A tunnel to a gateway the domain's relay does not name cuts nothing.
#[test]
fn another_domains_gateway_is_never_cut() {
    let domain = Domain::new("guard");
    let (peer, name) = workstation();
    let gateway = Gateway::admitting(&name, &peer);
    let mut target = domain.target(None);
    target.peer_key = WireGuardKey::from_bytes([0x62; 32]).to_base64();
    let (outcome, published) = drive(
        &domain,
        revoke(&peer, &name),
        &target,
        &gateway,
        &Tunnel::new(NO_ONE_ANSWERS).expect("tunnel"),
    );

    assert!(outcome.is_err());
    assert_eq!(gateway.reads.get(), 0);
    assert_eq!(gateway.cuts.get(), 0);
    assert_eq!(last_refusal(&published), Some(Refusal::HandoffMismatch));
}

/// Astra unreachable after the cut: the workstation stays cut and the refusal says so.
#[test]
fn cut_happens_without_astra() {
    let domain = Domain::new("cut");
    let (peer, name) = workstation();
    let gateway = Gateway::admitting(&name, &peer);
    let target = domain.target(None);
    let (outcome, published) = drive(
        &domain,
        revoke(&peer, &name),
        &target,
        &gateway,
        &Tunnel::new(NO_ONE_ANSWERS).expect("tunnel"),
    );

    assert!(outcome.is_err());
    assert_eq!(gateway.cuts.get(), 1, "the admission is withdrawn");
    assert_eq!(
        last_refusal(&published),
        Some(Refusal::AuthorityUnreachable)
    );
    assert_eq!(
        published.last().map(|status| status.gesture),
        Some(GestureState::Failed)
    );
    // The cut was published before Astra was asked anything.
    let cut_at = published
        .iter()
        .position(|status| status.refusal.is_none() && status.gesture == GestureState::Idle);
    assert!(cut_at.is_some(), "the cut is shown before the campaign");
}
