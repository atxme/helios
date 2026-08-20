//! The `astra` binary, run the way an operator runs it.
//!
//! `src/main.rs` is argument parsing, file layout and refusals — none of which
//! the library tests reach. What is checked here is the part an operator
//! depends on and a unit test cannot see: that `bootstrap` writes a usable
//! state directory, that it refuses to start a second history over an existing
//! one, that `status` reads back the same audit head, and that a missing
//! registry is an error rather than an empty domain.
//!
//! # Limite connue
//!
//! `run` is not exercised: it binds a socket and serves until killed, so a
//! test of it would be a test of `axum::serve`. What `run` adds on top of
//! `status` — loading the delegated issuer and refusing incoherent private
//! material — is covered by `issuer::tests` on the function that does it.

use std::path::Path;
use std::process::{Command, Output};

use aether::certificates::encoding::generate_ml_dsa_87_keypair;

fn astra(state_dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_astra"))
        .arg("--state-dir")
        .arg(state_dir)
        .args(args)
        .output()
        .expect("running the astra binary")
}

/// A public `CA-PQ` key, base64 — the one input `bootstrap` refuses to invent.
fn ca_public_key() -> String {
    let (_, public) = generate_ml_dsa_87_keypair().expect("keygen");
    public.to_base64()
}

fn bootstrap(state_dir: &Path, ca_public_key: &str) -> Output {
    astra(
        state_dir,
        &[
            "bootstrap",
            "--ca-public-key",
            ca_public_key,
            "--trust-domain-id",
            "0102030405060708090a0b0c0d0e0f10",
            "--gateway-wireguard-public-key",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            "--server-name",
            "gateway.example",
            "--authority-url",
            "https://astra.example",
            "--webauthn-rp-id",
            "astra.example",
        ],
    )
}

/// The nominal path, and the head an operator is told to record.
#[test]
fn bootstrap_writes_a_registry_and_status_reads_the_same_audit_head() {
    let directory = tempfile::tempdir().expect("temp dir");
    let output = bootstrap(directory.path(), &ca_public_key());
    assert!(
        output.status.success(),
        "bootstrap failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let printed = String::from_utf8(output.stdout).expect("utf-8");
    // Split on the colon rather than on a fixed prefix: the labels are padded
    // so an operator can read the block, and a test that pins the padding
    // fails on a column change while proving nothing.
    let head = printed
        .lines()
        .find(|line| line.trim_start().starts_with("audit head"))
        .and_then(|line| line.split_once(':'))
        .map(|(_, value)| value.trim().to_string())
        .expect("bootstrap prints the audit head");
    assert!(
        !head.is_empty(),
        "the audit head is printed, not just labelled"
    );
    assert!(directory.path().join("registry.json").exists());
    assert!(
        directory.path().join("service-key.bin").exists(),
        "the service key is Astra's own voice and is sealed at bootstrap"
    );

    let output = astra(directory.path(), &["status"]);
    assert!(output.status.success());
    let printed = String::from_utf8(output.stdout).expect("utf-8");
    assert!(printed.contains(&head), "status reports the same head");
    assert!(printed.contains("gateway.example"));
    assert!(
        printed.contains("delegated issuer : absent"),
        "a fresh domain has no delegation, and says so"
    );
}

/// Bootstrapping over an existing registry would start a second history for
/// one domain — two heads, and no way to tell a restore from a fork.
#[test]
fn bootstrap_refuses_to_run_over_an_existing_registry() {
    let directory = tempfile::tempdir().expect("temp dir");
    let key = ca_public_key();
    assert!(bootstrap(directory.path(), &key).status.success());

    let output = bootstrap(directory.path(), &key);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("second history"));
}

/// An anchor that is not an ML-DSA-87 key is refused at the boundary: Astra
/// never creates `CA-PQ`, so an unreadable one has no fallback.
#[test]
fn bootstrap_refuses_an_unreadable_anchor() {
    let directory = tempfile::tempdir().expect("temp dir");
    let output = bootstrap(directory.path(), "not-a-key");
    assert!(!output.status.success());
    assert!(!directory.path().join("registry.json").exists());
}

/// A missing registry is not an empty domain.
#[test]
fn status_on_an_unbootstrapped_directory_fails() {
    let directory = tempfile::tempdir().expect("temp dir");
    let output = astra(directory.path(), &["status"]);
    assert!(!output.status.success());
}

/// The delegation request is public, and it is the whole handover: an operator
/// pipes it out of the container and hands it to the companion. What must be
/// true of it is that the private halves exist here **before** it is printed —
/// a request naming a public key nobody holds would only be discovered after a
/// ceremony with a security key already plugged in.
#[test]
fn an_issuer_request_names_keys_this_state_directory_holds() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());

    let output = astra(directory.path(), &["issuer", "request"]);
    assert!(
        output.status.success(),
        "issuer request failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let request: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("the request is JSON on standard output");
    assert_eq!(
        request["issuer_epoch"], 1,
        "the first delegation is epoch 1"
    );
    assert_eq!(
        request["trust_domain_id"], "0102030405060708090a0b0c0d0e0f10",
        "the request names the domain it is for"
    );
    assert!(!request["pq_issuer_public_key"]
        .as_str()
        .expect("key")
        .is_empty());
    assert!(!request["tls_intermediate_csr"]
        .as_str()
        .expect("csr")
        .is_empty());
    assert!(directory.path().join("issuer-pq-key-1.bin").exists());
    assert!(directory.path().join("issuer-tls-key-1.der").exists());
}

/// Installing is not believing a file. An authorization that does not verify
/// under this domain's anchor is refused before anything is recorded — and the
/// authority keeps saying it has no issuer, which is the state that refuses
/// renewals by name rather than issuing under a delegation nobody signed.
#[test]
fn an_unsigned_delegation_is_refused_and_records_nothing() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    assert!(astra(directory.path(), &["issuer", "request"])
        .status
        .success());

    // Everything an authorization needs, except a signature anyone made.
    let forged = serde_json::json!({
        "format_version": 1,
        "trust_domain_id": "0102030405060708090a0b0c0d0e0f10",
        "ca_epoch": 1,
        "ca_tls_epoch": 1,
        "gateway_wg_public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        "server_name": "gateway.example",
        "issuer_epoch": 1,
        "pq_issuer_public_key": ca_public_key(),
        "tls_intermediate_certificate": "AQID",
        "allowed_usage": "admitted_client_leaf_renewal",
        "maximum_leaf_lifetime_secs": 3600,
        "policy_fingerprint": "00".repeat(32),
        "not_before": 0,
        "not_after": 4_000_000_000u64,
        "ca_pq_signature": "",
    });
    let path = directory.path().join("forged.json");
    std::fs::write(&path, serde_json::to_vec(&forged).expect("json")).expect("write");

    let output = astra(
        directory.path(),
        &[
            "issuer",
            "install",
            "--authorization",
            path.to_str().unwrap(),
        ],
    );
    assert!(
        !output.status.success(),
        "an unsigned delegation must not install"
    );
    let status = astra(directory.path(), &["status"]);
    let printed = String::from_utf8(status.stdout).expect("utf-8");
    assert!(
        printed.contains("delegated issuer : absent"),
        "nothing is recorded by a refused install: {printed}"
    );
}
