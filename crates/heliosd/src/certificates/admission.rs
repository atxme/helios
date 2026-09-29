//! The admission inbox, and the first generation of an admitted peer.

use super::*;

/// One admission, as the console leaves it for the daemon.
///
/// # Why an inbox and not a direct write
///
/// `heliosd peer add` runs in another process, and the daemon holds the
/// registry **in memory**: a second writer would either be overwritten at the
/// daemon's next persist, or would overwrite a staging in flight. So the
/// console writes what it knows — the two public leaves — and the daemon, which
/// is the single owner, performs the admission. It is the same shape as
/// `network.toml` being watched rather than pushed, and for the same reason.
///
/// Everything here is public. A file left behind by a daemon that was not
/// running is drained at its next start, which is what makes an offline
/// `peer add` followed by a boot equivalent to an online one.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueuedAdmission {
    pub name: String,
    pub client_wg_public_key: String,
    /// The TLS leaf, DER in base64.
    pub tls_certificate: String,
    /// The PQ leaf, its JSON document in base64.
    pub pq_certificate: String,
}

/// Where the console leaves admissions for the daemon.
///
/// Beside the registry rather than at a fixed path, so a test — and a
/// `--dev` daemon — keeps both in the same disposable directory.
pub fn admission_inbox(registry_path: &std::path::Path) -> PathBuf {
    registry_path
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("admissions")
}

/// Leaves one admission for the daemon to record.
///
/// Named by the peer's WireGuard key, so a re-run of the same admission
/// replaces its own file instead of queueing a second one.
pub fn queue_admission(
    registry_path: &std::path::Path,
    admission: &QueuedAdmission,
) -> Result<PathBuf> {
    let directory = admission_inbox(registry_path);
    aether::private_file::create_private_dir(&directory)
        .with_context(|| format!("creating {}", directory.display()))?;
    let name = format!(
        "{}.json",
        aether::certificates::encoding::Fingerprint::of(admission.client_wg_public_key.as_bytes())
            .to_hex()
    );
    let path = directory.join(name);
    let encoded = serde_json::to_vec_pretty(admission).context("encoding the admission")?;
    aether::private_file::write_private_atomic(&path, &encoded)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(path)
}

/// How often the daemon looks for admissions left by the console.
///
/// The same cadence as `network.toml` is watched at, and for the same reason:
/// an operator admits a peer and then immediately asks for its trust block.
/// Nothing is read unless a file is there, so the cost between two admissions
/// is one `read_dir` on an empty directory.
pub const ADMISSION_POLL_INTERVAL_SECS: u64 = 2;

/// Records the admissions the console left, and forgets the ones it recorded.
///
/// A refusal deletes the file too, and says so loudly: a queued admission that
/// this gateway will never accept — a leaf naming another peer, a window
/// already closed — would otherwise be retried every two seconds for as long
/// as the daemon runs, and the operator would read the same line for ever
/// instead of re-admitting.
pub fn spawn_admission_drain(service: Arc<CertificateService>, registry_path: PathBuf) {
    tokio::spawn(async move {
        let directory = admission_inbox(&registry_path);
        let mut ticker =
            tokio::time::interval(std::time::Duration::from_secs(ADMISSION_POLL_INTERVAL_SECS));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            let Ok(entries) = std::fs::read_dir(&directory) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                    continue;
                }
                match service.record_queued_admission(&path).await {
                    Ok(name) => {
                        tracing::info!(peer = %name, "console admission recorded");
                    }
                    Err(error) => {
                        tracing::error!(
                            file = %path.display(),
                            %error,
                            "console admission refused: this peer has no certificate generation, \
                             so it will connect but never renew. Re-admit it."
                        );
                    }
                }
                let _ = std::fs::remove_file(&path);
            }
        }
    });
}
