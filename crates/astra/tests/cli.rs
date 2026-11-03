//! The `astra` binary, run the way an operator runs it.
//!
//! `src/main.rs` is argument parsing, file layout and refusals — none of which
//! the library tests reach. What is checked here is the part an operator
//! depends on and a unit test cannot see: that `bootstrap` writes a usable
//! state directory, that it refuses to start a second history over an existing
//! one, that `status` reads back the same audit head, and that a missing
//! registry is an error rather than an empty domain.
//!
//! The console is a connector of the door (spec §5.5): an opening reaches the
//! running service over its socket or is refused, and a write goes through
//! that socket only while the service holds the volume. Both halves are run
//! here against a real `astra run`, started on a free loopback port and a
//! temporary volume, and stopped when the test ends, whether it passed or not.
//! What `run` adds on top — loading the delegated issuer and refusing
//! incoherent private material — is covered by `issuer::tests` on the
//! function that does it.

use std::path::Path;
use std::process::{Command, Output};

use aether::certificates::encoding::generate_ml_dsa_87_keypair;
use astra::registry::AstraRegistry;
use astra::AuditEvent;

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

/// A release that used to audit every read can leave status-only records after
/// the operator witness. The compatibility check accepts exactly that suffix,
/// while the normal exact-head check remains strict for every authority
/// decision.
#[test]
fn status_accepts_only_a_legacy_status_suffix_after_the_witness() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());

    let registry_path = directory.path().join("registry.json");
    let mut registry = AstraRegistry::load(&registry_path, None).expect("registry");
    let witness = registry.audit_head().to_hex();
    registry
        .record(
            AuditEvent::StatusPublished {
                target: "workstation".into(),
                status_epoch: 1,
            },
            2,
        )
        .expect("legacy status record");
    let current = registry.audit_head().to_hex();

    let output = astra(
        directory.path(),
        &["status", "--expected-audit-head", witness.as_str()],
    );
    assert!(
        output.status.success(),
        "status-only suffix rejected: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains(&current));

    registry
        .record(AuditEvent::IssuerInstalled { issuer_epoch: 2 }, 3)
        .expect("decision record");
    let output = astra(
        directory.path(),
        &["status", "--expected-audit-head", witness.as_str()],
    );
    assert!(
        !output.status.success(),
        "a decision suffix must remain a fork"
    );
}

/// Rewrites the registry in the shape an older Astra left: no policy pin and
/// no credential epoch, the two fields loading derives rather than refuses.
/// Returns the bytes now on disk.
fn age_the_registry(state_dir: &Path) -> Vec<u8> {
    let path = state_dir.join("registry.json");
    let mut document: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("registry")).expect("json");
    let object = document.as_object_mut().expect("object");
    object.remove("astra_policy_fingerprint");
    object.remove("credential_registry_epoch");
    let aged = serde_json::to_vec_pretty(&document).expect("encode");
    std::fs::write(&path, &aged).expect("write");
    aged
}

/// `status` is a reader: with the service possibly running, it must not
/// write the registry behind it (spec §5.9), even when the file it reads
/// still needs the migration loading performs. It prints the same domain.
#[test]
fn status_reads_a_registry_that_needs_migration_without_writing_it() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    let current = astra(directory.path(), &["status"]);
    assert!(current.status.success());

    let aged = age_the_registry(directory.path());
    let output = astra(directory.path(), &["status"]);
    assert!(
        output.status.success(),
        "status refused an older registry: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&current.stdout),
        "the migrated domain reads as the current one"
    );
    assert_eq!(
        std::fs::read(directory.path().join("registry.json")).expect("registry"),
        aged,
        "status wrote the registry"
    );
}

/// `astra chain status`, with the service's log silenced: what it prints for
/// the operator goes to stderr too, and log lines carry their timestamp.
fn chain_status(state_dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_astra"))
        .env("RUST_LOG", "off")
        .arg("--state-dir")
        .arg(state_dir)
        .args(["chain", "status"])
        .output()
        .expect("running the astra binary")
}

/// `chain status` is a reader too, and is held to the same rule as `status`.
/// The plan's current step is deposited, so the registry is actually
/// consulted for whether it landed.
#[test]
fn chain_status_reads_a_registry_that_needs_migration_without_writing_it() {
    use aether::certificates::encoding::{Fingerprint, Id16};
    use astra::chain::{ChainPlan, CHAIN_PLAN_FILE};

    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    let registry =
        AstraRegistry::load(&directory.path().join("registry.json"), None).expect("registry");
    let mut plan = ChainPlan::resolve(
        Id16::new([3; 16]).expect("id"),
        registry.state(),
        "annual rotation".into(),
        "operator".into(),
        300,
        1,
    );
    plan.record_deposit(
        Id16::new([4; 16]).expect("id"),
        Id16::new([5; 16]).expect("id"),
        Fingerprint::of(b"campaign"),
        2,
    )
    .expect("deposit");
    std::fs::write(
        directory.path().join(CHAIN_PLAN_FILE),
        serde_json::to_vec(&plan).expect("plan"),
    )
    .expect("write plan");
    let current = chain_status(directory.path());
    assert!(
        current.status.success(),
        "chain status: {}",
        String::from_utf8_lossy(&current.stderr)
    );
    assert!(
        String::from_utf8_lossy(&current.stderr).contains("has not taken effect yet"),
        "the registry was read for the deposited step: {}",
        String::from_utf8_lossy(&current.stderr)
    );

    let aged = age_the_registry(directory.path());
    let output = chain_status(directory.path());
    assert!(
        output.status.success(),
        "chain status refused an older registry: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stderr),
        String::from_utf8_lossy(&current.stderr),
        "the migrated domain reads as the current one"
    );
    assert_eq!(output.stdout, current.stdout);
    assert_eq!(
        std::fs::read(directory.path().join("registry.json")).expect("registry"),
        aged,
        "chain status wrote the registry"
    );
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
    let _service = RunningService::start(directory.path());

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
    // Through the running service, both of them: the request is an opening,
    // and the install is a write the service holds the volume for.
    let _service = RunningService::start(directory.path());
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
        // Well formed, so that the door is the one refusing it: a signature
        // nobody made.
        "ca_pq_signature": aether::certificates::encoding::MlDsa87Signature::placeholder(),
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
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("cette délégation ne s'installe pas ici, et rien n'a été enregistré"),
        "the door's refusal reaches the console whole: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let status = astra(directory.path(), &["status"]);
    let printed = String::from_utf8(status.stdout).expect("utf-8");
    assert!(
        printed.contains("delegated issuer : absent"),
        "nothing is recorded by a refused install: {printed}"
    );
}

/// The files of a state directory, with their bytes.
fn snapshot(state_dir: &Path) -> Vec<(std::ffi::OsString, Vec<u8>)> {
    let mut files: Vec<_> = std::fs::read_dir(state_dir)
        .expect("state dir")
        .map(|entry| {
            let entry = entry.expect("entry");
            (
                entry.file_name(),
                std::fs::read(entry.path()).expect("readable file"),
            )
        })
        .collect();
    files.sort();
    files
}

/// A service started while a console holds the volume — the bootstrap of
/// `deploy.sh`, then an `up -d` too early — refuses by name and writes
/// nothing: two writers of `/var/lib/astra` are a registry corruption.
#[test]
fn the_service_does_not_start_while_the_volume_is_held() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    let _held = astra::door::VolumeLock::try_acquire(directory.path())
        .expect("lockable")
        .expect("the test holds the volume");
    let before = snapshot(directory.path());

    let mut child = Command::new(env!("CARGO_BIN_EXE_astra"))
        .arg("--state-dir")
        .arg(directory.path())
        .args(["run", "--bind", "127.0.0.1:0"])
        .env_remove("ASTRA_GATEWAY_CHANNEL")
        .env_remove("ASTRA_PRIVATE_BIND")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("running the astra binary");
    // A service that ignored the lock would serve until killed: bounded, so
    // that the failure is a refusal of this test rather than a hang.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    while child.try_wait().expect("waiting").is_none() {
        if std::time::Instant::now() > deadline {
            child
                .kill()
                .expect("stopping the service this test started");
            let _ = child.wait();
            panic!("astra run started although the volume is held");
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let output = child.wait_with_output().expect("output");
    assert!(!output.status.success());
    let printed = String::from_utf8(output.stderr).expect("utf-8");
    assert!(
        printed.contains(&format!(
            "un autre processus tient {} : rien n'a démarré",
            directory.path().display()
        )),
        "the refusal names the volume: {printed}"
    );
    assert_eq!(
        snapshot(directory.path()),
        before,
        "nothing in the volume is touched"
    );
}

/// The sentence an opening is refused with when no service is running.
const SERVICE_STOPPED: &str = "le service Astra ne tourne pas : rien n'a été ouvert";

/// The admitted workstation of the tests that revoke one.
const WORKSTATION_KEY: [u8; 32] = [7; 32];
/// Its generation's signed expiry, the `--not-after` a revocation prints.
const WORKSTATION_NOT_AFTER: u64 = 4_000_000_000;

/// `astra run` on a temporary volume and a free loopback port, until dropped.
///
/// Dropped when the test ends, a panic included: the child is killed and
/// reaped there, so a failing test never leaves a service behind it.
struct RunningService {
    child: std::process::Child,
    log: tempfile::NamedTempFile,
}

impl RunningService {
    /// Starts the service and waits until its door socket answers.
    fn start(state_dir: &Path) -> Self {
        let log = tempfile::NamedTempFile::new().expect("service log");
        let child = Command::new(env!("CARGO_BIN_EXE_astra"))
            .arg("--state-dir")
            .arg(state_dir)
            .args(["run", "--bind", "127.0.0.1:0"])
            .env_remove("ASTRA_GATEWAY_CHANNEL")
            .env_remove("ASTRA_GATEWAY_CERTIFICATE")
            .env_remove("ASTRA_PRIVATE_BIND")
            .env_remove("ASTRA_GATEWAY_CLIENT_CERTIFICATE")
            .stdout(std::process::Stdio::null())
            .stderr(log.reopen().expect("log handle"))
            .spawn()
            .expect("running the astra binary");
        let mut service = Self { child, log };
        let socket = state_dir.join(astra::door::DOOR_SOCKET_FILE);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
        loop {
            if std::os::unix::net::UnixStream::connect(&socket).is_ok() {
                return service;
            }
            if let Some(status) = service.child.try_wait().expect("waiting") {
                panic!("astra run exited ({status}): {}", service.log());
            }
            if std::time::Instant::now() > deadline {
                panic!("astra run never opened its door: {}", service.log());
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    fn log(&self) -> String {
        std::fs::read_to_string(self.log.path()).unwrap_or_default()
    }
}

impl Drop for RunningService {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A placeholder vault: the service holds its bytes and never parses them,
/// and a scope that makes a master key sign is refused without one.
fn copy_a_vault(state_dir: &Path) {
    std::fs::write(
        state_dir.join("authority-vault.json"),
        b"placeholder encrypted vault",
    )
    .expect("vault");
}

/// Transcribes one admitted workstation, as the gateway's answer would.
fn admit_a_workstation(state_dir: &Path) -> aether::certificates::encoding::WireGuardKey {
    use aether::certificates::client::ClientCertificateGeneration;
    use aether::certificates::encoding::{Fingerprint, WireGuardKey};
    use aether::key_negotiation::{PqCertificate, PqCertificateRole, PQ_CERTIFICATE_VERSION};

    let key = WireGuardKey::from_bytes(WORKSTATION_KEY);
    let mut registry =
        AstraRegistry::load(&state_dir.join("registry.json"), None).expect("registry");
    registry
        .admit(
            astra::PeerRecord {
                name: "workstation".into(),
                client_wg_public_key: key,
                active: ClientCertificateGeneration {
                    generation: 4,
                    ca_tls_epoch: 1,
                    tls_ca_certificate_fingerprint: Fingerprint::of(b"client tls ca"),
                    tls_certificate_fingerprint: Fingerprint::of(b"workstation tls"),
                    pq_certificate_fingerprint: Fingerprint::of(b"workstation pq"),
                    not_before: 0,
                    not_after: WORKSTATION_NOT_AFTER,
                },
                active_pq_certificate: PqCertificate {
                    version: PQ_CERTIFICATE_VERSION,
                    serial: [7; 16],
                    subject: "workstation".into(),
                    issuer: "CA-PQ".into(),
                    role: PqCertificateRole::Client,
                    wireguard_public_key: key.to_base64(),
                    ml_dsa_87_public_key: String::new(),
                    not_before_unix: 0,
                    not_after_unix: WORKSTATION_NOT_AFTER,
                    ml_dsa_87_signature: String::new(),
                },
                pending: None,
                revoked: false,
                revocation_epoch: 0,
                admission_pq_ca: None,
            },
            1,
        )
        .expect("admitted");
    key
}

/// With the service stopped, nothing is opened, and nothing is left on disk
/// for a service to pick up later: a campaign lives in the service's memory,
/// so without it there is nothing to open (spec §5.5).
#[test]
fn an_opening_without_the_service_is_refused_and_writes_nothing() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    copy_a_vault(directory.path());
    let peer = admit_a_workstation(directory.path()).to_base64();
    let before = snapshot(directory.path());

    let text = ["--reason", "quarterly rotation", "--requested-by", "alice"];
    let openings: Vec<Vec<&str>> = vec![
        [&["campaign", "open", "--scope", "fleet-leafs"][..], &text].concat(),
        [
            &["campaign", "open", "--scope", "trust-authorities"][..],
            &text,
        ]
        .concat(),
        [
            &["revocation", "open", "--scope", "client", "--peer", &peer][..],
            &text,
        ]
        .concat(),
        [&["revocation", "open", "--scope", "gateway"][..], &text].concat(),
        [&["gateway-identity", "open"][..], &text].concat(),
        [&["chain", "open"][..], &text].concat(),
        vec!["chain", "next"],
        vec!["chain", "abandon"],
        vec!["issuer", "request"],
        [&["issuer", "request"][..], &text].concat(),
    ];
    for opening in openings {
        let output = astra(directory.path(), &opening);
        assert!(!output.status.success(), "{opening:?} succeeded");
        let printed = String::from_utf8_lossy(&output.stderr);
        assert!(
            printed.contains(SERVICE_STOPPED),
            "{opening:?} is refused by name: {printed}"
        );
        assert!(output.stdout.is_empty(), "{opening:?} printed an answer");
        assert_eq!(
            snapshot(directory.path()),
            before,
            "{opening:?} wrote into the volume"
        );
    }
}

/// The path `scripts/deploy.sh` takes: the service is stopped, the console
/// obtains the volume and writes the registry itself, and prints what it
/// always printed.
#[test]
fn pin_ca_tls_with_the_service_stopped_writes_locally() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    let fingerprint = "ab".repeat(32);

    let output = astra(
        directory.path(),
        &["pin-ca-tls", "--fingerprint", &fingerprint],
    );
    assert!(
        output.status.success(),
        "pin-ca-tls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{fingerprint}\n")
    );
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("ancre CA-TLS épinglée : la rotation du §9.4 est désormais vérifiable ici"));
    let registry =
        AstraRegistry::load(&directory.path().join("registry.json"), None).expect("registry");
    assert_eq!(
        registry
            .state()
            .ca_tls_fingerprint
            .map(|pinned| pinned.to_hex()),
        Some(fingerprint.clone())
    );

    // A deployment runs it on every pass: the anchor already held is no
    // refusal, and changes nothing.
    let output = astra(
        directory.path(),
        &["pin-ca-tls", "--fingerprint", &fingerprint],
    );
    assert!(output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr)
        .contains("cette ancre CA-TLS est déjà épinglée ; rien n'a changé"));
}

/// A service that crashed leaves its socket behind. A write decides by the
/// lock, never by the socket: the lock is free, so no service runs, and the
/// console writes locally instead of failing on a socket nobody listens to.
#[test]
fn a_write_with_a_stale_socket_and_a_free_lock_writes_locally() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    let socket = directory.path().join(astra::door::DOOR_SOCKET_FILE);
    drop(std::os::unix::net::UnixListener::bind(&socket).expect("stale socket"));
    assert!(socket.exists(), "the stale socket stays on disk");

    let fingerprint = "cd".repeat(32);
    let output = astra(
        directory.path(),
        &["pin-ca-tls", "--fingerprint", &fingerprint],
    );
    assert!(
        output.status.success(),
        "pin-ca-tls failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let registry =
        AstraRegistry::load(&directory.path().join("registry.json"), None).expect("registry");
    assert_eq!(
        registry
            .state()
            .ca_tls_fingerprint
            .map(|pinned| pinned.to_hex()),
        Some(fingerprint)
    );
}

/// `bootstrap` writes the volume, so it needs the volume to itself.
#[test]
fn bootstrap_refuses_while_the_volume_is_held() {
    let directory = tempfile::tempdir().expect("temp dir");
    let _held = astra::door::VolumeLock::try_acquire(directory.path())
        .expect("lockable")
        .expect("the test holds the volume");

    let output = bootstrap(directory.path(), &ca_public_key());
    assert!(!output.status.success());
    let printed = String::from_utf8_lossy(&output.stderr);
    assert!(
        printed.contains(&format!(
            "un autre processus tient {}",
            directory.path().display()
        )),
        "the refusal names the volume: {printed}"
    );
    assert!(!directory.path().join("registry.json").exists());
    assert!(!directory.path().join("service-key.bin").exists());
}

/// The registry is looked for under the volume lock, not before it: two
/// bootstraps that both looked first could both find nothing, and the second
/// would overwrite the domain the first had just created. With the volume
/// held, the refusal is the lock's, whatever the volume holds.
#[test]
fn bootstrap_looks_for_a_registry_only_once_it_holds_the_volume() {
    let directory = tempfile::tempdir().expect("temp dir");
    let key = ca_public_key();
    assert!(bootstrap(directory.path(), &key).status.success());
    let _held = astra::door::VolumeLock::try_acquire(directory.path())
        .expect("lockable")
        .expect("the test holds the volume");
    let before = snapshot(directory.path());

    let output = bootstrap(directory.path(), &key);
    assert!(!output.status.success());
    let printed = String::from_utf8_lossy(&output.stderr);
    assert!(
        printed.contains(&format!(
            "un autre processus tient {} : rien n'a été amorcé",
            directory.path().display()
        )),
        "the registry was looked for before the lock was taken: {printed}"
    );
    assert_eq!(
        snapshot(directory.path()),
        before,
        "nothing in the volume is touched"
    );
}

/// A write whose volume is held by a process that does not answer at the
/// door — a console mid-write, or a service that has not opened its socket —
/// is refused by name, and the registry is left as it was.
#[test]
fn a_write_while_a_mute_process_holds_the_volume_is_refused() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    let _held = astra::door::VolumeLock::try_acquire(directory.path())
        .expect("lockable")
        .expect("the test holds the volume");
    let before = snapshot(directory.path());

    let output = astra(
        directory.path(),
        &["pin-ca-tls", "--fingerprint", &"ab".repeat(32)],
    );
    assert!(!output.status.success(), "the write went through");
    let printed = String::from_utf8_lossy(&output.stderr);
    assert!(
        printed.contains(
            "un autre processus tient le volume, et le service Astra n'y répond pas : rien \
             n'a été écrit"
        ),
        "the refusal names the held volume: {printed}"
    );
    assert!(output.stdout.is_empty());
    assert_eq!(
        snapshot(directory.path()),
        before,
        "the registry is left byte for byte"
    );
}

/// The `--out` of a delegation request is opened before the door is called.
/// Written only after the answer, an unwritable path would leave a live
/// delegation campaign in the service, blocking its family for nothing; and
/// an opening refused leaves no empty file behind.
#[test]
fn an_unwritable_issuer_request_out_opens_nothing() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    copy_a_vault(directory.path());
    let elsewhere = tempfile::tempdir().expect("temp dir");
    let out = elsewhere.path().join("request.json");
    let out = out.to_str().expect("utf-8 path");
    let request = [
        "issuer",
        "request",
        "--reason",
        "annual delegation",
        "--requested-by",
        "alice",
    ];

    let output = astra(directory.path(), &[&request[..], &["--out", out]].concat());
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains(SERVICE_STOPPED));
    assert!(
        !Path::new(out).exists(),
        "a refused opening leaves no file at --out"
    );

    let service = RunningService::start(directory.path());
    let unwritable = elsewhere.path().join("missing").join("request.json");
    let output = astra(
        directory.path(),
        &[
            &request[..],
            &["--out", unwritable.to_str().expect("utf-8 path")],
        ]
        .concat(),
    );
    assert!(!output.status.success(), "an unwritable --out was accepted");
    let printed = String::from_utf8_lossy(&output.stderr);
    assert!(
        printed.contains(&format!("writing {}", unwritable.display())),
        "the refusal names the path: {printed}"
    );
    assert!(output.stdout.is_empty());

    let output = astra(directory.path(), &[&request[..], &["--out", out]].concat());
    assert!(
        output.status.success(),
        "the refused --out left a campaign behind: {} — service: {}",
        String::from_utf8_lossy(&output.stderr),
        service.log()
    );
    assert_eq!(
        std::fs::read(out).expect("the request is written"),
        String::from_utf8(output.stdout)
            .expect("utf-8")
            .trim_end()
            .as_bytes(),
        "--out holds the request printed on standard output"
    );
}

/// The opening reaches the running service: the identifier comes back, and a
/// second identical opening is refused because the first one is in the
/// service's own store.
#[test]
fn campaign_open_goes_through_the_running_service() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    copy_a_vault(directory.path());
    let service = RunningService::start(directory.path());

    let open = [
        "campaign",
        "open",
        "--scope",
        "trust-authorities",
        "--reason",
        "quarterly rotation",
        "--requested-by",
        "alice",
        "--window-secs",
        "120",
    ];
    let output = astra(directory.path(), &open);
    assert!(
        output.status.success(),
        "campaign open failed: {} — service: {}",
        String::from_utf8_lossy(&output.stderr),
        service.log()
    );
    let operation_id = String::from_utf8(output.stdout).expect("utf-8");
    let operation_id = operation_id.trim_end();
    assert_eq!(operation_id.len(), 32, "a hex operation id: {operation_id}");
    let printed = String::from_utf8_lossy(&output.stderr);
    assert!(
        printed.contains("campagne déposée : 2 credential(s), fenêtre de 120 s"),
        "{printed}"
    );
    assert!(printed.contains("empreinte de campagne : "), "{printed}");
    assert!(
        printed.contains(&format!(
            "approuver depuis le poste opérateur :\n  astra-signer approve-campaign \\\n    \
             --authority-url https://astra.example \\\n    --operation-id {operation_id}"
        )),
        "{printed}"
    );

    let output = astra(directory.path(), &open);
    assert!(!output.status.success(), "a second opening was accepted");
    let printed = String::from_utf8_lossy(&output.stderr);
    assert!(
        printed.contains(&format!(
            "une opération de la même famille attend déjà l'opérateur ({operation_id})"
        )),
        "the first opening is the one the service holds: {printed}"
    );
}

/// The revocation prints the whole `astra-signer revoke` line, with the
/// generation's signed expiry: the docs and the companion read it as is.
#[test]
fn revocation_open_prints_the_full_revoke_line() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    copy_a_vault(directory.path());
    let peer = admit_a_workstation(directory.path()).to_base64();
    let service = RunningService::start(directory.path());

    let output = astra(
        directory.path(),
        &[
            "revocation",
            "open",
            "--scope",
            "client",
            "--peer",
            &peer,
            "--reason",
            "stolen laptop",
            "--requested-by",
            "alice",
        ],
    );
    assert!(
        output.status.success(),
        "revocation open failed: {} — service: {}",
        String::from_utf8_lossy(&output.stderr),
        service.log()
    );
    let operation_id = String::from_utf8(output.stdout).expect("utf-8");
    let operation_id = operation_id.trim_end();
    let printed = String::from_utf8_lossy(&output.stderr);
    assert!(
        printed.contains(
            "révocation déposée : workstation, génération 4, compteur 1, fenêtre de 300 s"
        ),
        "{printed}"
    );
    assert!(
        printed.contains(&format!(
            "signer depuis le poste opérateur :\n  astra-signer revoke --authority-url \
             https://astra.example --operation-id {operation_id} --not-after \
             {WORKSTATION_NOT_AFTER}"
        )),
        "{printed}"
    );
}

/// With the service running, a write goes to it: the console never opens the
/// registry, and the service persists the pin itself.
#[test]
fn pin_ca_tls_goes_through_the_running_service() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    let service = RunningService::start(directory.path());
    let fingerprint = "ef".repeat(32);

    let output = astra(
        directory.path(),
        &["pin-ca-tls", "--fingerprint", &fingerprint],
    );
    assert!(
        output.status.success(),
        "pin-ca-tls failed: {} — service: {}",
        String::from_utf8_lossy(&output.stderr),
        service.log()
    );
    assert_eq!(
        String::from_utf8_lossy(&output.stdout),
        format!("{fingerprint}\n")
    );
    assert!(
        service
            .log()
            .contains("client CA-TLS anchor pinned through the door"),
        "the service performed the write: {}",
        service.log()
    );
    let registry =
        AstraRegistry::load(&directory.path().join("registry.json"), None).expect("registry");
    assert_eq!(
        registry
            .state()
            .ca_tls_fingerprint
            .map(|pinned| pinned.to_hex()),
        Some(fingerprint)
    );
}

/// A container stop is a `SIGTERM`: the service ends cleanly and takes its
/// socket with it, so the next console sees no service rather than a mute one.
#[test]
fn a_stopped_service_removes_its_socket() {
    let directory = tempfile::tempdir().expect("temp dir");
    assert!(bootstrap(directory.path(), &ca_public_key())
        .status
        .success());
    let mut service = RunningService::start(directory.path());
    let socket = directory.path().join(astra::door::DOOR_SOCKET_FILE);
    assert!(socket.exists());

    let signalled = Command::new("kill")
        .args(["-TERM", &service.child.id().to_string()])
        .status()
        .expect("signalling the service this test started");
    assert!(signalled.success());
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(60);
    let status = loop {
        if let Some(status) = service.child.try_wait().expect("waiting") {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "astra run ignored SIGTERM: {}",
            service.log()
        );
        std::thread::sleep(std::time::Duration::from_millis(50));
    };
    assert!(status.success(), "a clean stop: {}", service.log());
    assert!(!socket.exists(), "the socket is gone: {}", service.log());
}

/// Every source file of the console's commands, named: the check below reads
/// exactly these, and refuses a command file it was not told about.
const CONSOLE_SOURCES: [&str; 8] = [
    "src/commands.rs",
    "src/commands/campaign.rs",
    "src/commands/chain.rs",
    "src/commands/gateway_identity.rs",
    "src/commands/issuer.rs",
    "src/commands/revocation.rs",
    "src/commands/trust_domain.rs",
    "src/console.rs",
];

/// What reads the service key or reaches the registry file.
const REGISTRY_AND_KEY_NAMES: [&str; 6] = [
    "SERVICE_KEY_FILE",
    "service-key.bin",
    "AstraRegistry::load",
    "AstraRegistry::new",
    "REGISTRY_FILE",
    "registry.json",
];

/// The only functions that may name them, and which: `bootstrap` creates the
/// volume under its lock, `status` and `chain status` read it through
/// `AstraRegistry::read_state*`, never `load`, which writes back a migration,
/// and the console's local writer runs `door::write` under the volume lock.
const ALLOWED_USES: [(&str, &str, &str); 7] = [
    (
        "src/commands/trust_domain.rs",
        "bootstrap",
        "SERVICE_KEY_FILE",
    ),
    (
        "src/commands/trust_domain.rs",
        "bootstrap",
        "AstraRegistry::new",
    ),
    ("src/commands/trust_domain.rs", "bootstrap", "REGISTRY_FILE"),
    ("src/commands/trust_domain.rs", "status", "REGISTRY_FILE"),
    ("src/commands/chain.rs", "chain_status", "REGISTRY_FILE"),
    ("src/console.rs", "write_locally", "AstraRegistry::load"),
    ("src/console.rs", "write_locally", "REGISTRY_FILE"),
];

/// The function a line of code belongs to, when it opens one.
fn function_name(line: &str) -> Option<&str> {
    let (_, rest) = line.split_once("fn ")?;
    let name = rest.split(['(', '<']).next()?.trim();
    (!name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_')).then_some(name)
}

/// The service key never leaves the service, and the registry has one writer
/// (spec §5.5, §5.9): no opener of the console reads either. A search over
/// the sources rather than a runtime check, so that the next opener added to
/// a command file is held to it before anyone runs it.
#[test]
fn no_console_command_reads_the_service_key_or_writes_the_registry() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let mut on_disk: Vec<String> = std::fs::read_dir(root.join("src/commands"))
        .expect("commands directory")
        .map(|entry| {
            format!(
                "src/commands/{}",
                entry.expect("entry").file_name().to_string_lossy()
            )
        })
        .collect();
    on_disk.sort();
    let mut named: Vec<String> = CONSOLE_SOURCES
        .iter()
        .filter(|file| file.starts_with("src/commands/"))
        .map(|file| file.to_string())
        .collect();
    named.sort();
    assert_eq!(on_disk, named, "a command file this check does not read");

    let mut offences = Vec::new();
    for file in CONSOLE_SOURCES {
        let source = std::fs::read_to_string(root.join(file)).expect("source");
        let mut function = None;
        let mut in_use = false;
        for (number, line) in source.lines().enumerate() {
            let code = line.trim_start();
            if code.starts_with("//") {
                continue;
            }
            if code.starts_with("use ") || code.starts_with("pub(crate) use ") {
                in_use = true;
            }
            if let Some(name) = function_name(code) {
                function = Some(name.to_string());
            }
            for name in REGISTRY_AND_KEY_NAMES {
                if !line.contains(name) {
                    continue;
                }
                // An import reads nothing; renaming one would hide every use
                // from this check, so that is refused.
                let allowed = if in_use {
                    !line.contains(" as ")
                } else {
                    ALLOWED_USES
                        .iter()
                        .any(|(allowed_file, allowed_function, allowed)| {
                            *allowed_file == file
                                && function.as_deref() == Some(*allowed_function)
                                && *allowed == name
                        })
                };
                if !allowed {
                    offences.push(format!(
                        "{file}:{}: `{name}` in {}",
                        number + 1,
                        function.as_deref().unwrap_or("no function")
                    ));
                }
            }
            if in_use && code.ends_with(';') {
                in_use = false;
            }
        }
    }
    assert!(
        offences.is_empty(),
        "the console reads the service key or reaches the registry outside bootstrap, status and \
         the locked local write:\n{}",
        offences.join("\n")
    );
}
