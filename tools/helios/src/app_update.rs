//! Remote application updates from the operator workstation (ADR-003).
//!
//! The gateway remains the authority: this client checks the obvious local
//! mismatches before spending bandwidth, then sends the signed manifest and
//! exact ELF through the same JSON API as the web console. The privileged
//! installer re-verifies both and owns activation and rollback.

use std::{
    fs,
    io::{BufRead as _, Write as _},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

use aether::sig::SignedBinaryRelease;
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use helios_update::{FinalizedRelease, UpdateStatus};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::api;

const CHUNK_SIZE: usize = helios_update::MAX_CHUNK_SIZE;
const ACTIVATION_TIMEOUT: Duration = Duration::from_secs(75);
const STATUS_INTERVAL: Duration = Duration::from_secs(1);

pub struct Options {
    pub manifest: PathBuf,
    pub binary: PathBuf,
    pub stage_only: bool,
    pub yes: bool,
}

#[derive(Serialize)]
struct StageBody<'a> {
    manifest: &'a SignedBinaryRelease,
}

#[derive(Serialize)]
struct ChunkBody {
    release_sequence: u64,
    offset: u64,
    data: String,
}

#[derive(Serialize)]
struct SequenceBody {
    release_sequence: u64,
}

#[derive(Serialize)]
struct ActivateBody {
    release_sequence: u64,
    confirmation: String,
}

#[derive(Deserialize)]
struct ReleaseResponse {
    release: FinalizedRelease,
}

#[derive(Deserialize)]
struct ChunkResponse {
    next_offset: u64,
}

#[derive(Deserialize)]
struct ActivationResponse {
    accepted: bool,
    release_sequence: u64,
}

pub async fn run(client: &Client, base: &str, options: Options) -> Result<()> {
    let manifest = read_manifest(&options.manifest)?;
    validate_binary(&options.binary, &manifest)?;

    let before = status(client, base)
        .await
        .context("reading the gateway update status")?;
    validate_gateway(&before, &manifest)?;
    let already_staged = staged_release(&before, &manifest)?;

    let size = manifest.payload.binary_size;
    let started = Instant::now();
    println!(
        "\n  release {} sequence {} ({} bytes)",
        manifest.payload.version, manifest.payload.release_sequence, size
    );
    println!("  staging through {base}/api/update");

    let finalized = if let Some(staged) = already_staged {
        println!("  exact release already staged and verified on the gateway");
        staged
    } else {
        let finalized = transfer(client, base, &manifest, &options.binary).await?;
        let elapsed = started.elapsed();
        let mib_per_second = if elapsed.is_zero() {
            0.0
        } else {
            size as f64 / 1_048_576.0 / elapsed.as_secs_f64()
        };
        println!(
            "  {} bytes verified by the gateway in {:.2}s ({:.1} MiB/s)",
            size,
            elapsed.as_secs_f64(),
            mib_per_second
        );
        finalized
    };

    if options.stage_only {
        println!(
            "  release staged; activate it by rerunning without --stage-only or from the web console"
        );
        return Ok(());
    }
    if !options.yes && !confirm_activation(&finalized)? {
        println!("  activation cancelled; the verified release remains staged");
        return Ok(());
    }

    activate(client, base, finalized.release_sequence).await?;
    println!("  activation accepted; waiting for the tunnel and daemon to return");
    wait_for_confirmation(client, base, &finalized).await?;
    println!(
        "  {} heliosd {} sequence {} is active",
        crate::ok(),
        finalized.version,
        finalized.release_sequence
    );
    Ok(())
}

fn read_manifest(path: &Path) -> Result<SignedBinaryRelease> {
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid signed release manifest {}", path.display()))
}

fn validate_binary(path: &Path, manifest: &SignedBinaryRelease) -> Result<()> {
    let metadata = fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    if metadata.len() != manifest.payload.binary_size {
        bail!(
            "binary size mismatch: {} has {} bytes, manifest expects {}",
            path.display(),
            metadata.len(),
            manifest.payload.binary_size
        );
    }
    let digest = helios_update::sha256_file(path)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("SHA-256 of {}", path.display()))?;
    if digest != manifest.payload.sha256 {
        bail!("binary SHA-256 does not match the signed manifest");
    }
    helios_update::verify_elf(path, &manifest.payload.target)
        .map_err(|error| anyhow::anyhow!(error.to_string()))
        .with_context(|| format!("ELF validation of {}", path.display()))
}

fn validate_gateway(status: &UpdateStatus, manifest: &SignedBinaryRelease) -> Result<()> {
    if status.channel != manifest.payload.channel {
        bail!(
            "gateway channel is {}, manifest channel is {}",
            status.channel,
            manifest.payload.channel
        );
    }
    if status.target != manifest.payload.target {
        bail!(
            "gateway target is {}, manifest target is {}",
            status.target,
            manifest.payload.target
        );
    }
    if manifest.payload.release_sequence <= status.highest_confirmed_sequence {
        bail!(
            "release sequence {} is not newer than confirmed sequence {}",
            manifest.payload.release_sequence,
            status.highest_confirmed_sequence
        );
    }
    if let Some(pending) = status.activation_pending {
        bail!("gateway already has activation sequence {pending} pending");
    }
    Ok(())
}

fn staged_release(
    status: &UpdateStatus,
    manifest: &SignedBinaryRelease,
) -> Result<Option<FinalizedRelease>> {
    let Some(staged) = status
        .staged
        .iter()
        .find(|release| release.release_sequence == manifest.payload.release_sequence)
    else {
        return Ok(None);
    };
    if staged.version != manifest.payload.version
        || staged.sha256 != hex::encode(manifest.payload.sha256)
    {
        bail!(
            "gateway already staged different metadata for sequence {}",
            staged.release_sequence
        );
    }
    Ok(Some(staged.clone()))
}

async fn status(client: &Client, base: &str) -> Result<UpdateStatus> {
    let response = client
        .get(format!("{base}/api/update"))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .context("connection refused — is heliosd reachable through the tunnel?")?;
    let status = response.status();
    let text = response.text().await.context("unreadable response body")?;
    if !status.is_success() {
        bail!("{} : {}", status, text.trim());
    }
    serde_json::from_str(&text)
        .with_context(|| format!("unexpected JSON response from /api/update: {text}"))
}

async fn transfer(
    client: &Client,
    base: &str,
    manifest: &SignedBinaryRelease,
    binary_path: &Path,
) -> Result<FinalizedRelease> {
    let sequence = manifest.payload.release_sequence;
    let staged: ReleaseResponse =
        api::post_json(client, base, "/api/update/stage", &StageBody { manifest })
            .await
            .context("staging the signed manifest")?;
    if staged.release.release_sequence != sequence {
        bail!("gateway staged a different release sequence");
    }

    let mut binary = tokio::fs::File::open(binary_path)
        .await
        .with_context(|| format!("opening {}", binary_path.display()))?;
    let mut buffer = vec![0u8; CHUNK_SIZE];
    let mut offset = 0u64;
    loop {
        let count = binary
            .read(&mut buffer)
            .await
            .with_context(|| format!("reading {}", binary_path.display()))?;
        if count == 0 {
            break;
        }
        let response: ChunkResponse = api::post_json(
            client,
            base,
            "/api/update/chunk",
            &ChunkBody {
                release_sequence: sequence,
                offset,
                data: STANDARD.encode(&buffer[..count]),
            },
        )
        .await
        .with_context(|| format!("uploading bytes {offset}..{}", offset + count as u64))?;
        let expected = offset + count as u64;
        if response.next_offset != expected {
            bail!(
                "gateway acknowledged offset {}, expected {expected}",
                response.next_offset
            );
        }
        offset = response.next_offset;
        print_progress(offset, manifest.payload.binary_size);
    }
    println!();

    if offset != manifest.payload.binary_size {
        bail!(
            "uploaded {offset} bytes, manifest expects {}",
            manifest.payload.binary_size
        );
    }
    let finalized: ReleaseResponse = api::post_json(
        client,
        base,
        "/api/update/finalize",
        &SequenceBody {
            release_sequence: sequence,
        },
    )
    .await
    .context("finalizing the uploaded binary")?;
    if finalized.release.release_sequence != sequence
        || finalized.release.version != manifest.payload.version
        || finalized.release.sha256 != hex::encode(manifest.payload.sha256)
    {
        bail!("gateway finalized metadata inconsistent with the signed manifest");
    }
    Ok(finalized.release)
}

fn print_progress(offset: u64, total: u64) {
    let percent = offset.saturating_mul(100).checked_div(total).unwrap_or(100);
    print!(
        "\r  upload {:>3}%  {offset}/{total} bytes",
        percent.min(100)
    );
    let _ = std::io::stdout().flush();
}

fn confirm_activation(release: &FinalizedRelease) -> Result<bool> {
    println!();
    println!(
        "Activate heliosd {} sequence {}? The tunnel will briefly disconnect.",
        release.version, release.release_sequence
    );
    print!("Proceed? [y/N] ");
    std::io::stdout().flush().ok();
    let mut answer = String::new();
    std::io::stdin()
        .lock()
        .read_line(&mut answer)
        .context("reading the confirmation")?;
    Ok(matches!(answer.trim(), "y" | "Y" | "yes"))
}

async fn activate(client: &Client, base: &str, sequence: u64) -> Result<()> {
    let response: ActivationResponse = api::post_json(
        client,
        base,
        "/api/update/activate",
        &ActivateBody {
            release_sequence: sequence,
            confirmation: format!("INSTALLER {sequence}"),
        },
    )
    .await
    .context("requesting activation")?;
    if !response.accepted || response.release_sequence != sequence {
        bail!("gateway did not accept activation sequence {sequence}");
    }
    Ok(())
}

async fn wait_for_confirmation(
    client: &Client,
    base: &str,
    release: &FinalizedRelease,
) -> Result<()> {
    let started = Instant::now();
    while started.elapsed() < ACTIVATION_TIMEOUT {
        if let Ok(status) = status(client, base).await {
            if status.highest_confirmed_sequence == release.release_sequence
                && status.active_version.as_deref() == Some(release.version.as_str())
            {
                return Ok(());
            }
        }
        tokio::time::sleep(STATUS_INTERVAL).await;
    }
    bail!(
        "release {} was not confirmed within {} seconds; the gateway may have rolled back",
        release.release_sequence,
        ACTIVATION_TIMEOUT.as_secs()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::sig::{ArtifactSignature, BinaryReleasePayload, SignedEnvelope};
    use tokio::io::AsyncWriteExt;

    const MOCK_SERVER_TIMEOUT: Duration = Duration::from_secs(5);

    fn directory(name: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "helios-app-update-{name}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).expect("test directory");
        path
    }

    fn x86_elf() -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[..6].copy_from_slice(b"\x7fELF\x02\x01");
        bytes[18..20].copy_from_slice(&62u16.to_le_bytes());
        bytes
    }

    fn manifest(binary: &Path, sequence: u64) -> SignedBinaryRelease {
        let metadata = fs::metadata(binary).unwrap();
        SignedEnvelope {
            payload: BinaryReleasePayload {
                product: "heliosd".into(),
                channel: "production".into(),
                release_sequence: sequence,
                version: "1.2.3".into(),
                git_commit: "0123456789abcdef".into(),
                target: "x86_64-unknown-linux-gnu".into(),
                features: vec!["wireguard".into()],
                binary_size: metadata.len(),
                sha256: helios_update::sha256_file(binary).unwrap(),
                minimum_installer_version: helios_update::INSTALLER_VERSION,
            },
            key_epoch: 1,
            signatures: vec![ArtifactSignature {
                alg: "test".into(),
                sig: "test".into(),
            }],
        }
    }

    fn write_inputs(root: &Path) -> (PathBuf, PathBuf, SignedBinaryRelease) {
        let binary = root.join("heliosd");
        let manifest_path = root.join("release.json");
        fs::write(&binary, x86_elf()).unwrap();
        let release = manifest(&binary, 42);
        fs::write(&manifest_path, serde_json::to_vec(&release).unwrap()).unwrap();
        (manifest_path, binary, release)
    }

    fn status_body(
        highest_confirmed_sequence: u64,
        active_version: Option<&str>,
        staged: &[FinalizedRelease],
        activation_pending: Option<u64>,
    ) -> String {
        serde_json::to_string(&UpdateStatus {
            highest_confirmed_sequence,
            active_version: active_version.map(str::to_owned),
            staged: staged.to_vec(),
            activation_pending,
            channel: "production".into(),
            target: "x86_64-unknown-linux-gnu".into(),
        })
        .unwrap()
    }

    fn finalized_body(release: &SignedBinaryRelease) -> String {
        serde_json::json!({
            "release": {
                "release_sequence": release.payload.release_sequence,
                "version": release.payload.version,
                "sha256": hex::encode(release.payload.sha256)
            }
        })
        .to_string()
    }

    fn test_client() -> Client {
        Client::builder().no_proxy().build().unwrap()
    }

    async fn within_test_timeout<F: std::future::Future>(future: F) -> F::Output {
        tokio::time::timeout(MOCK_SERVER_TIMEOUT, future)
            .await
            .expect("loopback update operation completes within its test deadline")
    }

    async fn finish_server(server: tokio::task::JoinHandle<Vec<String>>) -> Vec<String> {
        within_test_timeout(server)
            .await
            .expect("fake update server task completes")
    }

    async fn read_request(stream: &mut tokio::net::TcpStream) -> String {
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let read = stream.read(&mut buffer).await.expect("read request");
            if read == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..read]);
            let Some(header_end) = request.windows(4).position(|part| part == b"\r\n\r\n") else {
                continue;
            };
            let header_end = header_end + 4;
            let headers = String::from_utf8_lossy(&request[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
                .unwrap_or(0);
            if request.len() >= header_end + content_length {
                break;
            }
        }
        String::from_utf8_lossy(&request).into_owned()
    }

    async fn response_server(
        responses: Vec<(&'static str, String)>,
    ) -> (String, tokio::task::JoinHandle<Vec<String>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("local listener");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, body) in responses {
                let (mut stream, _) = tokio::time::timeout(MOCK_SERVER_TIMEOUT, listener.accept())
                    .await
                    .expect("HTTP client connects within the test deadline")
                    .expect("HTTP request");
                requests.push(
                    tokio::time::timeout(MOCK_SERVER_TIMEOUT, read_request(&mut stream))
                        .await
                        .expect("HTTP request body completes within the test deadline"),
                );
                let response = format!(
                    "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write response");
            }
            requests
        });
        (format!("http://{address}"), task)
    }

    #[test]
    fn local_preflight_accepts_only_the_exact_elf() {
        let root = directory("preflight");
        let binary = root.join("heliosd");
        fs::write(&binary, x86_elf()).unwrap();
        let release = manifest(&binary, 42);
        validate_binary(&binary, &release).expect("matching ELF");

        fs::write(&binary, [0u8; 20]).unwrap();
        let error = validate_binary(&binary, &release).expect_err("changed ELF");
        assert!(error.to_string().contains("SHA-256"), "{error:#}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn gateway_preflight_rejects_channel_target_sequence_and_pending_activation() {
        let root = directory("gateway");
        let binary = root.join("heliosd");
        fs::write(&binary, x86_elf()).unwrap();
        let release = manifest(&binary, 42);
        let mut status = UpdateStatus {
            highest_confirmed_sequence: 41,
            active_version: Some("1.2.2".into()),
            staged: Vec::new(),
            activation_pending: None,
            channel: "production".into(),
            target: "x86_64-unknown-linux-gnu".into(),
        };
        validate_gateway(&status, &release).expect("compatible gateway");
        assert!(staged_release(&status, &release).unwrap().is_none());

        status.staged.push(FinalizedRelease {
            release_sequence: 42,
            version: "1.2.3".into(),
            sha256: hex::encode(release.payload.sha256),
        });
        assert_eq!(
            staged_release(&status, &release)
                .unwrap()
                .unwrap()
                .release_sequence,
            42
        );
        status.staged[0].sha256 = "different".into();
        assert!(staged_release(&status, &release).is_err());
        status.staged.clear();

        status.channel = "testing".into();
        assert!(validate_gateway(&status, &release).is_err());
        status.channel = "production".into();
        status.target = "aarch64-unknown-linux-gnu".into();
        assert!(validate_gateway(&status, &release).is_err());
        status.target = "x86_64-unknown-linux-gnu".into();
        status.highest_confirmed_sequence = 42;
        assert!(validate_gateway(&status, &release).is_err());
        status.highest_confirmed_sequence = 41;
        status.activation_pending = Some(40);
        assert!(validate_gateway(&status, &release).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn transfer_uses_the_staged_chunked_finalized_and_activation_contract() {
        let root = directory("transport");
        let binary = root.join("heliosd");
        fs::write(&binary, x86_elf()).unwrap();
        let release = manifest(&binary, 42);
        let sha256 = hex::encode(release.payload.sha256);
        let summary = format!(
            r#"{{"release":{{"release_sequence":42,"version":"1.2.3","sha256":"{sha256}"}}}}"#
        );
        let responses = vec![
            ("200 OK", summary.clone()),
            (
                "200 OK",
                format!(r#"{{"next_offset":{}}}"#, release.payload.binary_size),
            ),
            ("200 OK", summary),
            (
                "202 Accepted",
                r#"{"accepted":true,"release_sequence":42}"#.into(),
            ),
        ];
        let (base, server) = response_server(responses).await;
        let client = test_client();

        let finalized = transfer(&client, &base, &release, &binary)
            .await
            .expect("transfer");
        assert_eq!(finalized.release_sequence, 42);
        activate(&client, &base, 42).await.expect("activation");

        let requests = finish_server(server).await;
        assert_eq!(requests.len(), 4);
        for (request, route) in requests.iter().zip([
            "/api/update/stage",
            "/api/update/chunk",
            "/api/update/finalize",
            "/api/update/activate",
        ]) {
            assert!(request.starts_with(&format!("POST {route} ")), "{request}");
        }
        let chunk_body = requests[1].split_once("\r\n\r\n").unwrap().1;
        let chunk: serde_json::Value = serde_json::from_str(chunk_body).unwrap();
        assert_eq!(chunk["release_sequence"], 42);
        assert_eq!(chunk["offset"], 0);
        assert_eq!(
            STANDARD.decode(chunk["data"].as_str().unwrap()).unwrap(),
            x86_elf()
        );
        let activation_body = requests[3].split_once("\r\n\r\n").unwrap().1;
        let activation: serde_json::Value = serde_json::from_str(activation_body).unwrap();
        assert_eq!(activation["confirmation"], "INSTALLER 42");
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn run_stage_only_transfers_the_exact_release_without_requesting_activation() {
        let root = directory("run-stage-only");
        let (manifest_path, binary, release) = write_inputs(&root);
        let finalized = finalized_body(&release);
        let responses = vec![
            ("200 OK", status_body(41, Some("1.2.2"), &[], None)),
            ("200 OK", finalized.clone()),
            (
                "200 OK",
                format!(r#"{{"next_offset":{}}}"#, release.payload.binary_size),
            ),
            ("200 OK", finalized),
        ];
        let (base, server) = response_server(responses).await;

        within_test_timeout(run(
            &test_client(),
            &base,
            Options {
                manifest: manifest_path,
                binary,
                stage_only: true,
                yes: false,
            },
        ))
        .await
        .expect("stage-only run completes successfully");

        let requests = finish_server(server).await;
        assert_eq!(requests.len(), 4);
        assert!(requests[0].starts_with("GET /api/update HTTP/1.1"));
        for (request, route) in requests[1..].iter().zip([
            "/api/update/stage",
            "/api/update/chunk",
            "/api/update/finalize",
        ]) {
            assert!(request.starts_with(&format!("POST {route} ")), "{request}");
        }
        let chunk_body = requests[2].split_once("\r\n\r\n").unwrap().1;
        let chunk: serde_json::Value = serde_json::from_str(chunk_body).unwrap();
        assert_eq!(chunk["release_sequence"], 42);
        assert_eq!(chunk["offset"], 0);
        assert_eq!(
            STANDARD.decode(chunk["data"].as_str().unwrap()).unwrap(),
            x86_elf()
        );
        assert!(requests
            .iter()
            .all(|request| !request.contains("/activate")));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn run_resumes_an_exact_staged_release_without_reuploading_and_confirms_it() {
        let root = directory("run-resume");
        let (manifest_path, binary, release) = write_inputs(&root);
        let staged = FinalizedRelease {
            release_sequence: release.payload.release_sequence,
            version: release.payload.version.clone(),
            sha256: hex::encode(release.payload.sha256),
        };
        let responses = vec![
            (
                "200 OK",
                status_body(41, Some("1.2.2"), std::slice::from_ref(&staged), None),
            ),
            (
                "202 Accepted",
                r#"{"accepted":true,"release_sequence":42}"#.into(),
            ),
            ("200 OK", status_body(42, Some("1.2.3"), &[], None)),
        ];
        let (base, server) = response_server(responses).await;

        within_test_timeout(run(
            &test_client(),
            &base,
            Options {
                manifest: manifest_path,
                binary,
                stage_only: false,
                yes: true,
            },
        ))
        .await
        .expect("resumed activation completes, including confirmation polling");

        let requests = finish_server(server).await;
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with("GET /api/update HTTP/1.1"));
        assert!(requests[1].starts_with("POST /api/update/activate "));
        assert!(requests[2].starts_with("GET /api/update HTTP/1.1"));
        assert!(requests
            .iter()
            .all(|request| !request.contains("/api/update/stage")));
        let activation_body = requests[1].split_once("\r\n\r\n").unwrap().1;
        let activation: serde_json::Value = serde_json::from_str(activation_body).unwrap();
        assert_eq!(activation["release_sequence"], 42);
        assert_eq!(activation["confirmation"], "INSTALLER 42");
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn run_refuses_an_incompatible_gateway_before_any_update_mutation() {
        let root = directory("run-channel-refusal");
        let (manifest_path, binary, _) = write_inputs(&root);
        let (base, server) = response_server(vec![(
            "200 OK",
            serde_json::json!({
                "highest_confirmed_sequence": 41,
                "active_version": "1.2.2",
                "staged": [],
                "activation_pending": null,
                "channel": "testing",
                "target": "x86_64-unknown-linux-gnu"
            })
            .to_string(),
        )])
        .await;

        let error = within_test_timeout(run(
            &test_client(),
            &base,
            Options {
                manifest: manifest_path,
                binary,
                stage_only: true,
                yes: false,
            },
        ))
        .await
        .expect_err("testing gateway must refuse production release");

        assert!(error.to_string().contains("gateway channel is testing"));
        let requests = finish_server(server).await;
        assert_eq!(requests.len(), 1);
        assert!(requests[0].starts_with("GET /api/update HTTP/1.1"));
        let _ = fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn transfer_stops_when_the_gateway_acknowledges_the_wrong_offset() {
        let root = directory("wrong-offset");
        let binary = root.join("heliosd");
        fs::write(&binary, x86_elf()).unwrap();
        let release = manifest(&binary, 42);
        let responses = vec![
            ("200 OK", finalized_body(&release)),
            ("200 OK", r#"{"next_offset":19}"#.into()),
        ];
        let (base, server) = response_server(responses).await;

        let error = within_test_timeout(transfer(&test_client(), &base, &release, &binary))
            .await
            .expect_err("wrong byte offset must stop the transfer");
        assert!(error.to_string().contains("acknowledged offset 19"));

        let requests = finish_server(server).await;
        assert_eq!(requests.len(), 2);
        assert!(requests[0].starts_with("POST /api/update/stage "));
        assert!(requests[1].starts_with("POST /api/update/chunk "));
        let _ = fs::remove_dir_all(root);
    }
}
