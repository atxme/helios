use super::*;

use aether::certificates::authority::RotationReason;
use aether::certificates::client::IssuerKind;
use aether::certificates::encoding::Id16;
use aether::certificates::encoding::{generate_ml_dsa_87_keypair, DerCertificate};
use aether::certificates::gateway::AbortReason;
use aether::certificates::window::TransitionWindow;
use aether::key_negotiation::{issue_pq_certificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use zeroize::Zeroizing;

mod fixtures;
use fixtures::{
    client_key, domain, fixture, gateway_key, generation, keys, leaf, Fixture, Keys, SERVER_NAME,
};

mod distribution;
mod persistence;
mod staging;
mod transitions;
mod trust;

use distribution::distribution;
use staging::{authorization, commit_for, grant_for};
use transitions::{gateway_abort, gateway_transition, window};
