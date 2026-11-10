//! Firmware inventory and explicitly targeted operator-side maintenance.
//! Installation is orchestrated from outside the gateway so recovery keys and
//! transaction state survive a failed gateway boot (ADR-007).

use aether::sig::SignedFirmwareRecovery;
use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Subcommand;
use helios_tpm::firmware_recovery::{self, FirmwareBackup};
use serde::{Deserialize, Serialize};
use std::{
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

#[derive(Subcommand)]
pub enum FirmwareCmd {
    /// Lists firmware using existing fwupd metadata; local unless SSH is given.
    List {
        #[arg(long)]
        ssh_target: Option<String>,
    },
    /// Prepares a durable plan and encrypted TPM backup on the operator host.
    Prepare {
        #[arg(long)]
        ssh_target: String,
        #[arg(long)]
        device: String,
        #[arg(long)]
        target_version: String,
        #[arg(long)]
        plan: PathBuf,
        /// Operator escrow private key, on this workstation only.
        #[arg(long)]
        private_key: Option<PathBuf>,
    },
    /// Installs the prepared version, reboots, restores TPM and checks readiness.
    Update {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        authorization: Option<PathBuf>,
        #[arg(long)]
        private_key: Option<PathBuf>,
        #[arg(long)]
        yes: bool,
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(10..=3600))]
        timeout: u64,
    },
    /// Continues an interrupted reboot/recovery without ever reinstalling firmware.
    Resume {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        authorization: Option<PathBuf>,
        #[arg(long)]
        private_key: Option<PathBuf>,
        /// Confirms an interrupted installer has finished, after inspection on the gateway.
        #[arg(long)]
        confirm_installed: bool,
        #[arg(long, default_value_t = 300, value_parser = clap::value_parser!(u64).range(10..=3600))]
        timeout: u64,
    },
    /// Shows saved progress without contacting the gateway or opening secrets.
    Status {
        #[arg(long)]
        plan: PathBuf,
    },
}

#[derive(Debug, thiserror::Error)]
pub enum FirmwareError {
    #[error("Secure Boot packages change PCR 0/7 and are outside the OS update window; use the prepared firmware recovery workflow for fwupd updates")]
    RecoveryRequired,
    #[error("invalid firmware device identifier: expected the 40-character hexadecimal DeviceId")]
    InvalidDeviceId,
    #[error("installer outcome is uncertain; inspect fwupd on the gateway, then explicitly use firmware resume --confirm-installed. Helios will never repeat the installation")]
    InstallationUncertain,
    #[error("the gateway did not return with a new boot and verified readiness in time; use firmware resume with the same plan, or the gateway console if SSH is unavailable")]
    GatewayUnavailable,
}

#[derive(Deserialize)]
struct FirmwareInventory {
    #[serde(rename = "Devices")]
    devices: Vec<FirmwareDevice>,
}
#[derive(Debug, Deserialize)]
struct FirmwareDevice {
    #[serde(rename = "DeviceId")]
    id: String,
    #[serde(rename = "Name")]
    name: String,
    #[serde(rename = "Version")]
    version: String,
    #[serde(rename = "Releases", default)]
    releases: Vec<FirmwareRelease>,
    #[serde(rename = "UpdateError", default)]
    update_error: Option<String>,
    #[serde(rename = "UpdateState", default)]
    update_state: Option<u32>,
}
#[derive(Debug, Deserialize)]
struct FirmwareRelease {
    #[serde(rename = "Version")]
    version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Identity {
    machine: String,
    boot: String,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Prepared,
    Installing,
    Installed,
    RebootRequested,
    Restoring,
    Verifying,
    Complete,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    format_version: u32,
    ssh_target: String,
    before: Identity,
    device: String,
    target_version: String,
    backup: Option<FirmwareBackup>,
    phase: Phase,
    after_boot: Option<String>,
}

pub fn run(command: FirmwareCmd) -> Result<()> {
    match command {
        FirmwareCmd::List { ssh_target } => match ssh_target {
            None => list(),
            Some(target) => {
                report(&SshGateway::new(&target)?.inventory(true)?);
                Ok(())
            }
        },
        FirmwareCmd::Prepare {
            ssh_target,
            device,
            target_version,
            plan,
            private_key,
        } => prepare(
            &ssh_target,
            &device,
            &target_version,
            &plan,
            private_key.as_deref(),
        ),
        FirmwareCmd::Update {
            plan,
            authorization,
            private_key,
            yes,
            timeout,
        } => maintain(
            &plan,
            authorization.as_deref(),
            private_key.as_deref(),
            Some(yes),
            false,
            timeout,
        ),
        FirmwareCmd::Resume {
            plan,
            authorization,
            private_key,
            confirm_installed,
            timeout,
        } => maintain(
            &plan,
            authorization.as_deref(),
            private_key.as_deref(),
            None,
            confirm_installed,
            timeout,
        ),
        FirmwareCmd::Status { plan } => {
            let plan = load_plan(&plan)?;
            println!(
                "Gateway: {}\nDevice: {}\nVersion: {}\nPhase: {:?}\nTPM backup: {}",
                plan.ssh_target,
                plan.device,
                plan.target_version,
                plan.phase,
                plan.backup.is_some()
            );
            Ok(())
        }
    }
}

pub fn list() -> Result<()> {
    let output = Command::new("fwupdmgr")
        .args(["get-updates", "--json"])
        .output()
        .context("running fwupdmgr — install fwupd to inspect firmware")?;
    report(&parse_fwupd_output(output, true)?);
    Ok(())
}
fn valid_device_id(id: &str) -> Result<()> {
    anyhow::ensure!(
        id.len() == 40 && id.bytes().all(|b| b.is_ascii_hexdigit()),
        FirmwareError::InvalidDeviceId
    );
    Ok(())
}
fn valid_version(version: &str) -> Result<()> {
    anyhow::ensure!(
        !version.is_empty()
            && !version.starts_with('-')
            && version.len() <= 128
            && version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b)),
        "invalid firmware version"
    );
    Ok(())
}
fn parse_inventory(output: &[u8], updates_only: bool) -> Result<Vec<FirmwareDevice>> {
    let mut inventory: FirmwareInventory = serde_json::from_slice(output)
        .context("unexpected fwupd JSON — inventory is unknown, not empty")?;
    for device in &inventory.devices {
        valid_device_id(&device.id)?;
        anyhow::ensure!(
            !device.name.trim().is_empty()
                && !device.version.trim().is_empty()
                && device
                    .releases
                    .iter()
                    .all(|release| !release.version.trim().is_empty()),
            "incomplete fwupd device or release"
        );
    }
    if updates_only {
        inventory
            .devices
            .retain(|device| !device.releases.is_empty());
    }
    Ok(inventory.devices)
}
fn parse_fwupd_output(output: Output, updates_only: bool) -> Result<Vec<FirmwareDevice>> {
    anyhow::ensure!(
        output.status.success() || (updates_only && output.status.code() == Some(2)),
        "fwupd inventory failed ({}): {}",
        output.status,
        terminal_text(&String::from_utf8_lossy(&output.stderr))
    );
    if updates_only && output.status.code() == Some(2) && output.stdout.is_empty() {
        return Ok(Vec::new());
    }
    parse_inventory(&output.stdout, updates_only)
}
fn terminal_text(value: &str) -> String {
    value.chars().filter(|c| !c.is_control()).collect()
}
fn report(devices: &[FirmwareDevice]) {
    if devices.is_empty() {
        println!("No firmware updates in current fwupd metadata.");
    }
    for device in devices {
        println!(
            "{}: {} → {}\n  DeviceId: {}",
            terminal_text(&device.name),
            terminal_text(&device.version),
            device
                .releases
                .iter()
                .map(|r| terminal_text(&r.version))
                .collect::<Vec<_>>()
                .join(", "),
            device.id
        );
    }
}

trait Gateway {
    fn identity(&mut self) -> Result<Identity>;
    fn check_installer(&mut self) -> Result<()>;
    fn sealing(&mut self) -> Result<bool>;
    fn inventory(&mut self, updates_only: bool) -> Result<Vec<FirmwareDevice>>;
    fn export(&mut self, public: &[u8], device: &str, version: &str) -> Result<FirmwareBackup>;
    fn preflight(&mut self, auth: &[u8]) -> Result<()>;
    fn stop(&mut self) -> Result<()>;
    fn install(&mut self, device: &str, version: &str) -> Result<()>;
    fn reboot(&mut self) -> Result<()>;
    fn restore(&mut self, frame: &[u8]) -> Result<()>;
    fn start_and_check(&mut self) -> Result<()>;
}

struct SshGateway {
    target: String,
    port: Option<String>,
}
impl SshGateway {
    fn new(target: &str) -> Result<Self> {
        orion_core::profile_import::validate_ssh_target(target)?;
        anyhow::ensure!(
            target == target.trim(),
            "SSH target must not contain surrounding whitespace"
        );
        let (target, port) = target
            .rsplit_once(':')
            .map_or((target, None), |(host, port)| (host, Some(port.to_owned())));
        Ok(Self {
            target: target.into(),
            port,
        })
    }
    fn execute(&self, command: &str, input: &[u8]) -> Result<Output> {
        let mut process = Command::new("ssh");
        process.args([
            "-T",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ServerAliveInterval=10",
            "-o",
            "ServerAliveCountMax=3",
        ]);
        if let Some(port) = &self.port {
            process.args(["-p", port]);
        }
        // Bound inspection, service and recovery commands even when SSH is
        // alive but the remote process hangs. Never kill a firmware flash on
        // an arbitrary timer: its ambiguous outcome requires inspection.
        let bounded = if command.starts_with("sudo -n fwupdmgr install ") {
            command.to_owned()
        } else {
            format!(
                "timeout --signal=TERM 30s sh -c {}",
                shlex::try_quote(command)?
            )
        };
        let mut child = process
            .arg(&self.target)
            .arg(bounded)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context(
                "starting authenticated SSH; configure keys and known_hosts before maintenance",
            )?;
        // Input frames are bounded to 64 KiB and never passed in arguments or
        // persisted on the gateway. SSH supplies authenticated encryption.
        if let Some(mut stdin) = child.stdin.take() {
            if let Err(error) = stdin.write_all(input) {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error).context("sending maintenance input through SSH");
            }
        }
        child.wait_with_output().context("waiting for SSH")
    }
    fn checked(&self, command: &str, input: &[u8]) -> Result<Vec<u8>> {
        let output = self.execute(command, input)?;
        anyhow::ensure!(
            output.status.success(),
            "gateway operation failed ({}): {}",
            output.status,
            terminal_text(&String::from_utf8_lossy(&output.stderr))
        );
        Ok(output.stdout)
    }
    fn tpm(&self, args: &str, input: &[u8]) -> Result<Vec<u8>> {
        self.checked(
            &format!("sudo -n /opt/helios/current/heliosd tpm {args}"),
            input,
        )
    }
}
impl Gateway for SshGateway {
    fn check_installer(&mut self) -> Result<()> {
        check_installer_version(&self.checked("fwupdmgr --version --json", &[])?)
    }
    fn identity(&mut self) -> Result<Identity> {
        let bytes = self.checked("cat /etc/machine-id /proc/sys/kernel/random/boot_id", &[])?;
        let text = std::str::from_utf8(&bytes)?;
        let lines: Vec<_> = text.lines().collect();
        anyhow::ensure!(
            lines.len() == 2
                && lines[0].len() == 32
                && lines[0].bytes().all(|b| b.is_ascii_hexdigit())
                && lines[1].len() == 36
                && lines[1].bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'),
            "invalid gateway machine or boot identity"
        );
        Ok(Identity {
            machine: lines[0].into(),
            boot: lines[1].into(),
        })
    }
    fn sealing(&mut self) -> Result<bool> {
        let bytes = self.tpm("sealing-status", &[])?;
        match std::str::from_utf8(&bytes)?.trim() {
            "enabled" => Ok(true),
            "disabled" => Ok(false),
            _ => anyhow::bail!("unknown TPM sealing status"),
        }
    }
    fn inventory(&mut self, updates_only: bool) -> Result<Vec<FirmwareDevice>> {
        parse_fwupd_output(
            self.execute(
                if updates_only {
                    "fwupdmgr get-updates --json"
                } else {
                    "fwupdmgr get-devices --json"
                },
                &[],
            )?,
            updates_only,
        )
    }
    fn export(&mut self, public: &[u8], device: &str, version: &str) -> Result<FirmwareBackup> {
        let args = format!("export-firmware --operator-public-key '{}' --device '{device}' --target-version '{version}'", B64.encode(public));
        serde_json::from_slice(&self.tpm(&args, &[])?).context("invalid encrypted firmware backup")
    }
    fn preflight(&mut self, auth: &[u8]) -> Result<()> {
        let out = self.tpm("firmware-preflight", auth)?;
        anyhow::ensure!(out == b"ready\n", "ambiguous firmware preflight response");
        Ok(())
    }
    fn stop(&mut self) -> Result<()> {
        self.checked("sudo -n systemctl stop heliosd.service", &[])?;
        Ok(())
    }
    fn install(&mut self, device: &str, version: &str) -> Result<()> {
        // Pin the device AND version. No --force, --no-safety-check, policy
        // override or unbounded all-device upgrade is introduced.
        let out = self.checked(
            &format!(
                "sudo -n fwupdmgr install '{device}' '{version}' --assume-yes --no-reboot-check"
            ),
            &[],
        )?;
        println!("{}", terminal_text(&String::from_utf8_lossy(&out)));
        Ok(())
    }
    fn reboot(&mut self) -> Result<()> {
        self.checked("sudo -n systemctl reboot", &[])?;
        Ok(())
    }
    fn restore(&mut self, frame: &[u8]) -> Result<()> {
        let out = self.tpm("restore-firmware", frame)?;
        anyhow::ensure!(
            out == b"restored\n" || out == b"unchanged\n",
            "ambiguous TPM restore response"
        );
        Ok(())
    }
    fn start_and_check(&mut self) -> Result<()> {
        self.checked("sudo -n systemctl start heliosd.service", &[])?;
        self.checked("systemctl is-active --quiet heliosd.service", &[])?;
        let ready = self.checked("sudo -n cat /run/helios/ready", &[])?;
        let ready = std::str::from_utf8(&ready)?;
        let pid = self.checked(
            "systemctl show --property=MainPID --value heliosd.service",
            &[],
        )?;
        let pid = std::str::from_utf8(&pid)?.trim();
        anyhow::ensure!(
            pid != "0"
                && pid.bytes().all(|b| b.is_ascii_digit())
                && ready.lines().any(|line| line == format!("pid={pid}")),
            "gateway readiness belongs to another service process"
        );
        anyhow::ensure!(
            ready.lines().any(|line| line == "mode_reel=true")
                && ready.lines().any(|line| line == "firewall_enforced=true"),
            "gateway has not published real, enforced readiness"
        );
        Ok(())
    }
}

fn ensure_external(machine: &str) -> Result<()> {
    let local = std::fs::read_to_string("/etc/machine-id")
        .context("cannot establish that this is a separate operator workstation")?;
    anyhow::ensure!(local.trim() != machine, "firmware maintenance must run from a separate operator workstation; keep recovery keys off the gateway");
    Ok(())
}
fn check_installer_version(bytes: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    struct Versions {
        #[serde(rename = "Versions")]
        versions: Vec<Version>,
    }
    #[derive(Deserialize)]
    struct Version {
        #[serde(rename = "Type")]
        kind: String,
        #[serde(rename = "AppstreamId")]
        id: String,
        #[serde(rename = "Version")]
        version: String,
    }
    let versions: Versions = serde_json::from_slice(bytes)
        .context("cannot establish fwupdmgr version before firmware maintenance")?;
    let clients: Vec<_> = versions
        .versions
        .iter()
        .filter(|v| v.kind == "compile" && v.id == "org.freedesktop.fwupd")
        .collect();
    anyhow::ensure!(clients.len() == 1, "ambiguous fwupdmgr client version");
    let parts: Vec<u64> = clients[0]
        .version
        .split('.')
        .map(str::parse)
        .collect::<std::result::Result<_, _>>()
        .context("unrecognized fwupdmgr client version")?;
    // 2.0.20 is the oldest verified CLI contract for install DEVICE-ID VERSION.
    // Legacy clients interpret install's arguments as firmware file paths.
    anyhow::ensure!(
        parts.len() == 3 && parts.as_slice() >= [2, 0, 20].as_slice(),
        "firmware maintenance requires fwupdmgr 2.0.20 or newer for device/version-pinned installation"
    );
    Ok(())
}
fn protect_memory() -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: these prctl operations only change/read this process's dump policy.
        anyhow::ensure!(
            unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0) } == 0,
            "cannot protect recovery secrets from process dumps: {}",
            std::io::Error::last_os_error()
        );
        anyhow::ensure!(
            unsafe { libc::prctl(libc::PR_GET_DUMPABLE) } == 0,
            "process dump protection did not apply"
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    anyhow::bail!("TPM firmware recovery currently requires a Linux operator workstation for process-memory protection")
}
fn private_key(path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    protect_memory()?;
    let mut text = Zeroizing::new(Vec::with_capacity(1026));
    std::fs::File::open(path)?
        .take(1025)
        .read_to_end(&mut text)?;
    anyhow::ensure!(text.len() <= 1024, "operator key exceeds its size limit");
    let key = Zeroizing::new(B64.decode(std::str::from_utf8(&text)?.trim())?);
    anyhow::ensure!(
        key.len() == 32,
        "operator escrow private key must contain 32 bytes"
    );
    Ok(key)
}
fn recover(backup: &FirmwareBackup, private_path: &Path) -> Result<Zeroizing<Vec<u8>>> {
    let key = private_key(private_path)?;
    let recovered = helios_escrow::open_as_operator(&key, &backup.encrypted_secret)?;
    firmware_recovery::check_secret(&backup.request, &recovered)?;
    Ok(recovered)
}
fn prepare(
    target: &str,
    device: &str,
    version: &str,
    path: &Path,
    private_path: Option<&Path>,
) -> Result<()> {
    valid_device_id(device)?;
    valid_version(version)?;
    let _lock = PlanLock::acquire(path)?;
    anyhow::ensure!(
        !path.try_exists()?,
        "plan already exists; choose a new plan or resume it"
    );
    let mut gateway = SshGateway::new(target)?;
    let before = gateway.identity()?;
    ensure_external(&before.machine)?;
    gateway.check_installer()?;
    let inventory = gateway.inventory(true)?;
    ensure_available(&inventory, device, version)?;
    let backup = if gateway.sealing()? {
        let key = private_key(private_path.context(
            "TPM firmware preparation requires --private-key from the operator escrow",
        )?)?;
        let secret = x25519_dalek::StaticSecret::from(<[u8; 32]>::try_from(key.as_slice())?);
        let public = x25519_dalek::PublicKey::from(&secret);
        let backup = gateway.export(public.as_bytes(), device, version)?;
        anyhow::ensure!(
            backup.request.device_id == device && backup.request.target_version == version,
            "gateway exported another firmware context"
        );
        let recovered = helios_escrow::open_as_operator(&key, &backup.encrypted_secret)?;
        firmware_recovery::check_secret(&backup.request, &recovered)?;
        Some(backup)
    } else {
        None
    };
    anyhow::ensure!(
        gateway.identity()? == before,
        "gateway rebooted during preparation; prepare again"
    );
    let plan = Plan {
        format_version: 1,
        ssh_target: target.into(),
        before,
        device: device.into(),
        target_version: version.into(),
        backup,
        phase: Phase::Prepared,
        after_boot: None,
    };
    save_plan(path, &plan, true)?;
    if let Some(backup) = &plan.backup {
        let request_path = path.with_extension("request.json");
        crate::files::write_new(
            &request_path,
            &serde_json::to_vec_pretty(&backup.request)?,
            true,
        )?;
        sync_parent(&request_path)?;
        println!(
            "Encrypted TPM backup verified. Have helios-publisher sign {} off the gateway.",
            request_path.display()
        );
    }
    println!(
        "Plan prepared: {}. Nothing installed or rebooted.",
        path.display()
    );
    Ok(())
}
fn ensure_available(devices: &[FirmwareDevice], device: &str, version: &str) -> Result<()> {
    anyhow::ensure!(
        devices
            .iter()
            .any(|d| d.id == device && d.releases.iter().any(|r| r.version == version)),
        "selected device/version is absent from available upgrades; refresh and prepare a new plan"
    );
    Ok(())
}

fn maintain(
    path: &Path,
    authorization: Option<&Path>,
    private_path: Option<&Path>,
    install: Option<bool>,
    confirm_installed: bool,
    timeout: u64,
) -> Result<()> {
    let _lock = PlanLock::acquire(path)?;
    let mut plan = load_plan(path)?;
    let mut gateway = SshGateway::new(&plan.ssh_target)?;
    let actual = gateway.identity()?;
    ensure_external(&actual.machine)?;
    anyhow::ensure!(
        actual.machine == plan.before.machine,
        "SSH target now points to another machine"
    );
    let credentials = if let Some(backup) = &mut plan.backup {
        let auth: SignedFirmwareRecovery = serde_json::from_slice(&read_bounded(
            authorization.context("TPM recovery requires --authorization")?,
            64 * 1024,
        )?)?;
        firmware_recovery::validate_authorization(&auth)?;
        // A counter-first interrupted restore can need a newer authorization;
        // its root, device and version context must remain exactly identical.
        let mut expected = backup.request.clone();
        expected.version = auth.payload.version;
        anyhow::ensure!(
            auth.payload == expected && auth.payload.version >= backup.request.version,
            "authorization differs from the prepared backup"
        );
        backup.request.version = auth.payload.version;
        let recovered = recover(
            backup,
            private_path.context("TPM recovery requires --private-key on this workstation")?,
        )?;
        let auth_json = serde_json::to_vec(&auth)?;
        let frame = firmware_recovery::encode_restore_frame(&auth, &recovered)?;
        let mut locked = aether::locked::LockedSecret::with_capacity(frame.len());
        locked.set(&frame)?;
        if !locked.lock_state().holds() {
            eprintln!("Recovery frame memory locking is unavailable; encrypted swap/volume protection is required (ADR-006).");
        }
        Some((auth_json, locked))
    } else {
        None
    };
    if plan.phase == Phase::Complete {
        println!("Firmware maintenance already completed.");
        return Ok(());
    }
    if let Some(yes) = install {
        anyhow::ensure!(
            plan.phase == Phase::Prepared,
            "installation has already started; use firmware resume"
        );
        let identity = gateway.identity()?;
        anyhow::ensure!(
            identity == plan.before,
            "gateway changed or rebooted; prepare a new plan before installation"
        );
        anyhow::ensure!(
            gateway.sealing()? == plan.backup.is_some(),
            "TPM posture changed since preparation"
        );
        ensure_available(
            &gateway.inventory(true)?,
            &plan.device,
            &plan.target_version,
        )?;
        if let Some((auth, _)) = &credentials {
            gateway.preflight(auth)?;
        }
        println!("Gateway {} · device {} · version {}\nThe gateway will stop and reboot. SSH must remain reachable independently of its VPN.", plan.ssh_target, plan.device, plan.target_version);
        if !yes && !crate::interactive::confirm("Install the firmware and reboot this gateway?")? {
            return Ok(());
        }
        install_prepared(
            &mut gateway,
            &mut plan,
            path,
            credentials.as_ref().map(|(auth, _)| auth.as_slice()),
        )?;
    } else if plan.phase == Phase::Installing {
        anyhow::ensure!(confirm_installed, FirmwareError::InstallationUncertain);
        anyhow::ensure!(
            crate::interactive::confirm(
                "Have you verified that fwupd finished installing this exact device/version?"
            )?,
            "installation remains uncertain"
        );
        plan.phase = Phase::Installed;
        save_plan(path, &plan, false)?;
    }
    anyhow::ensure!(
        plan.phase != Phase::Prepared,
        "nothing installed; use firmware update with this plan"
    );
    finish(
        &mut gateway,
        &mut plan,
        path,
        credentials.as_ref().map(|(_, frame)| frame.expose()),
        Duration::from_secs(timeout),
    )
}

fn install_prepared(
    gateway: &mut impl Gateway,
    plan: &mut Plan,
    path: &Path,
    auth: Option<&[u8]>,
) -> Result<()> {
    anyhow::ensure!(
        plan.phase == Phase::Prepared,
        "installation has already started; use firmware resume"
    );
    anyhow::ensure!(
        gateway.identity()? == plan.before,
        "gateway rebooted or changed during confirmation"
    );
    gateway.check_installer()?;
    anyhow::ensure!(
        gateway.sealing()? == plan.backup.is_some(),
        "TPM posture changed during confirmation"
    );
    ensure_available(
        &gateway.inventory(true)?,
        &plan.device,
        &plan.target_version,
    )?;
    if let Some(auth) = auth {
        gateway.preflight(auth)?;
    }
    plan.phase = Phase::Installing;
    save_plan(path, plan, false)?;
    gateway.stop()?;
    if let Some(auth) = auth {
        gateway.preflight(auth)?;
    }
    println!("Installing the prepared firmware version…");
    gateway.install(&plan.device, &plan.target_version)?;
    plan.phase = Phase::Installed;
    save_plan(path, plan, false)
}

fn finish(
    gateway: &mut impl Gateway,
    plan: &mut Plan,
    path: &Path,
    frame: Option<&[u8]>,
    timeout: Duration,
) -> Result<()> {
    anyhow::ensure!(
        matches!(
            plan.phase,
            Phase::Installed | Phase::RebootRequested | Phase::Restoring | Phase::Verifying
        ),
        FirmwareError::InstallationUncertain
    );
    let deadline = Instant::now() + timeout;
    if plan.phase == Phase::Installed {
        let identity = gateway.identity()?;
        anyhow::ensure!(
            identity.machine == plan.before.machine,
            "SSH target now points to another machine"
        );
        plan.phase = Phase::RebootRequested;
        save_plan(path, plan, false)?;
        if identity.boot == plan.before.boot {
            // A lost SSH response is ambiguous: retain reboot intent and wait
            // for a changed boot_id, rather than issuing repeated reboots.
            if let Err(error) = gateway.reboot() {
                eprintln!("Reboot response unavailable: {error:#}; checking the next boot.");
            }
        }
    }
    loop {
        if Instant::now() >= deadline {
            return Err(FirmwareError::GatewayUnavailable.into());
        }
        match try_finish(gateway, plan, path, frame) {
            Ok(true) => {
                println!(
                    "Firmware version and real gateway readiness verified. Maintenance complete."
                );
                return Ok(());
            }
            Ok(false) => {}
            Err(error) => {
                eprintln!("Gateway not ready: {error:#}");
            }
        }
        std::thread::sleep(
            Duration::from_secs(3).min(deadline.saturating_duration_since(Instant::now())),
        );
    }
}
fn try_finish(
    gateway: &mut impl Gateway,
    plan: &mut Plan,
    path: &Path,
    frame: Option<&[u8]>,
) -> Result<bool> {
    let identity = gateway.identity()?;
    anyhow::ensure!(
        identity.machine == plan.before.machine,
        "SSH target now points to another machine"
    );
    if identity.boot == plan.before.boot {
        return Ok(false);
    }
    if let Some(after) = &plan.after_boot {
        anyhow::ensure!(
            after == &identity.boot,
            "gateway rebooted again during recovery; inspect it before continuing"
        );
    } else {
        plan.after_boot = Some(identity.boot.clone());
        save_plan(path, plan, false)?;
    }
    // Verify the intended firmware before sending a root to the new boot.
    let devices = gateway.inventory(false)?;
    let device = devices
        .iter()
        .find(|d| d.id == plan.device)
        .context("updated device is missing")?;
    anyhow::ensure!(
        device.version == plan.target_version,
        "firmware version is {}, expected {}",
        terminal_text(&device.version),
        plan.target_version
    );
    anyhow::ensure!(
        device
            .update_error
            .as_deref()
            .unwrap_or_default()
            .is_empty(),
        "fwupd reports an installation error"
    );
    anyhow::ensure!(
        matches!(device.update_state, None | Some(0 | 2)),
        "fwupd has not confirmed a successful firmware installation"
    );
    if matches!(plan.phase, Phase::RebootRequested | Phase::Restoring) {
        plan.phase = Phase::Restoring;
        save_plan(path, plan, false)?;
        anyhow::ensure!(
            gateway.sealing()? == plan.backup.is_some(),
            "gateway TPM posture changed"
        );
        if let Some(frame) = frame {
            gateway.stop()?;
            gateway.restore(frame)?;
        }
        plan.phase = Phase::Verifying;
        save_plan(path, plan, false)?;
    }
    gateway.start_and_check()?;
    let after = gateway.identity()?;
    anyhow::ensure!(
        after == identity,
        "gateway rebooted during readiness verification"
    );
    plan.phase = Phase::Complete;
    save_plan(path, plan, false)?;
    Ok(true)
}

fn read_bounded(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)?
        .take(limit + 1)
        .read_to_end(&mut bytes)?;
    anyhow::ensure!(
        bytes.len() as u64 <= limit,
        "maintenance file exceeds its size limit"
    );
    Ok(bytes)
}
fn load_plan(path: &Path) -> Result<Plan> {
    let plan: Plan = serde_json::from_slice(&read_bounded(path, 64 * 1024)?)
        .context("invalid maintenance plan")?;
    anyhow::ensure!(
        plan.format_version == 1,
        "unsupported firmware plan version"
    );
    valid_device_id(&plan.device)?;
    valid_version(&plan.target_version)?;
    SshGateway::new(&plan.ssh_target)?;
    if let Some(backup) = &plan.backup {
        backup.request.validate().map_err(anyhow::Error::msg)?;
        anyhow::ensure!(
            backup.request.device_id == plan.device
                && backup.request.target_version == plan.target_version,
            "plan and encrypted backup have different firmware contexts"
        );
    }
    Ok(plan)
}
fn sync_parent(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}
fn save_plan(path: &Path, plan: &Plan, create: bool) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(plan)?;
    if create {
        crate::files::write_new(path, &bytes, true)?;
        return sync_parent(path);
    }
    aether::private_file::write_private_atomic(path, &bytes).context("saving firmware transaction")
}

/// OS advisory locking survives process crashes without leaving a stale lock.
struct PlanLock {
    _file: std::fs::File,
}
impl PlanLock {
    fn acquire(path: &Path) -> Result<Self> {
        #[cfg(target_os = "linux")]
        {
            use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
            let file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW)
                .open(path.with_extension("lock"))?;
            // SAFETY: valid owned fd; flock changes only its advisory lock.
            anyhow::ensure!(
                unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
                "another process is maintaining this plan: {}",
                std::io::Error::last_os_error()
            );
            Ok(Self { _file: file })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            anyhow::bail!("firmware transactions currently require a Linux operator workstation");
        }
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    const ID: &str = "5bc922b7bd1adb5b6f99592611404036bd9f42d0";
    #[test]
    fn malformed_inventory_is_unknown_and_device_selection_is_exact() {
        assert!(parse_inventory(br#"{"Devices":[]}"#, true)
            .unwrap()
            .is_empty());
        for bytes in [
            b"{}".as_slice(),
            b"not JSON",
            br#"{"Devices":[{"Name":"UEFI"}]}"#,
        ] {
            assert!(parse_inventory(bytes, true).is_err());
        }
        for id in ["", "--force", "all", "; reboot", "../../firmware.cab"] {
            assert!(valid_device_id(id).is_err());
        }
        for version in ["", "--force", "2023'; reboot", "2023\n"] {
            assert!(valid_version(version).is_err());
        }
    }
    #[test]
    fn installer_version_requires_a_known_device_version_pinning_contract() {
        for version in ["2.0.20", "2.1.1", "3.0.0"] {
            let bytes = serde_json::to_vec(&serde_json::json!({"Versions": [
                {"Type": "compile", "AppstreamId": "org.freedesktop.fwupd", "Version": version}
            ]}))
            .unwrap();
            check_installer_version(&bytes).unwrap();
        }
        for version in ["1.9.28", "2.0.19", "2.0", "2.0.20-custom", "unknown"] {
            let bytes = serde_json::to_vec(&serde_json::json!({"Versions": [
                {"Type": "compile", "AppstreamId": "org.freedesktop.fwupd", "Version": version}
            ]}))
            .unwrap();
            assert!(check_installer_version(&bytes).is_err());
        }
        for bytes in [b"{}".as_slice(), br#"{"Versions":[]}"#, b"not JSON"] {
            assert!(check_installer_version(bytes).is_err());
        }
    }
    struct FakeGateway {
        identity: Identity,
        sealed: bool,
        events: Vec<String>,
        preflight_ok: bool,
        preflight_calls: usize,
        preflight_fail_at: Option<usize>,
        stop_ok: bool,
        installer_ok: bool,
        install_ok: bool,
        reboot_applies: bool,
        restore_ok: bool,
        restore_applied: bool,
        restore_applies_then_loses_reply: bool,
        restore_frame_fingerprints: Vec<aether::certificates::encoding::Fingerprint>,
        ready: bool,
        reboot_during_health: bool,
        version: String,
        update_state: Option<u32>,
    }
    impl Gateway for FakeGateway {
        fn check_installer(&mut self) -> Result<()> {
            anyhow::ensure!(self.installer_ok, "unsupported fwupdmgr client");
            Ok(())
        }
        fn identity(&mut self) -> Result<Identity> {
            Ok(self.identity.clone())
        }
        fn sealing(&mut self) -> Result<bool> {
            Ok(self.sealed)
        }
        fn inventory(&mut self, _: bool) -> Result<Vec<FirmwareDevice>> {
            Ok(vec![FirmwareDevice {
                id: ID.into(),
                name: "UEFI CA".into(),
                version: self.version.clone(),
                releases: vec![FirmwareRelease {
                    version: "2023".into(),
                }],
                update_error: None,
                update_state: self.update_state,
            }])
        }
        fn export(&mut self, _: &[u8], _: &str, _: &str) -> Result<FirmwareBackup> {
            anyhow::bail!("export not called in transaction tests")
        }
        fn preflight(&mut self, _: &[u8]) -> Result<()> {
            self.preflight_calls += 1;
            anyhow::ensure!(
                self.preflight_ok && self.preflight_fail_at != Some(self.preflight_calls),
                "invalid authorization"
            );
            Ok(())
        }
        fn stop(&mut self) -> Result<()> {
            self.events.push("stop".into());
            anyhow::ensure!(self.stop_ok, "service stop failed");
            Ok(())
        }
        fn install(&mut self, device: &str, version: &str) -> Result<()> {
            self.events.push(format!("install:{device}:{version}"));
            anyhow::ensure!(self.install_ok, "installer disconnected");
            Ok(())
        }
        fn reboot(&mut self) -> Result<()> {
            self.events.push("reboot".into());
            if self.reboot_applies {
                self.identity.boot = "new-boot".into();
                self.version = "2023".into();
            }
            anyhow::bail!("SSH response lost after reboot request")
        }
        fn restore(&mut self, frame: &[u8]) -> Result<()> {
            self.events.push("restore".into());
            self.restore_frame_fingerprints
                .push(aether::certificates::encoding::Fingerprint::of(frame));
            if self.restore_applies_then_loses_reply && !self.restore_applied {
                self.restore_applied = true;
                anyhow::bail!("SSH response lost after TPM restore was applied")
            }
            anyhow::ensure!(self.restore_ok, "restore unavailable");
            self.restore_applied = true;
            Ok(())
        }
        fn start_and_check(&mut self) -> Result<()> {
            self.events.push("health".into());
            anyhow::ensure!(self.ready, "service not ready");
            if self.reboot_during_health {
                self.identity.boot = "reboot-during-health".into();
            }
            Ok(())
        }
    }
    fn transaction(sealed: bool) -> (tempfile::TempDir, PathBuf, Plan, FakeGateway) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("maintenance.json");
        let identity = Identity {
            machine: "gateway".into(),
            boot: "old-boot".into(),
        };
        let backup = sealed.then(|| FirmwareBackup {
            request: aether::sig::FirmwareRecoveryPayload {
                version: 1,
                sealed_blob_anchor: [1; 32],
                secret_commitment: [2; 32],
                device_id: ID.into(),
                target_version: "2023".into(),
            },
            encrypted_secret: vec![],
        });
        let plan = Plan {
            format_version: 1,
            ssh_target: "operator@gateway".into(),
            before: identity.clone(),
            device: ID.into(),
            target_version: "2023".into(),
            backup,
            phase: Phase::Prepared,
            after_boot: None,
        };
        save_plan(&path, &plan, true).unwrap();
        let gateway = FakeGateway {
            identity,
            sealed,
            events: vec![],
            preflight_ok: true,
            preflight_calls: 0,
            preflight_fail_at: None,
            stop_ok: true,
            installer_ok: true,
            install_ok: true,
            reboot_applies: true,
            restore_ok: true,
            restore_applied: false,
            restore_applies_then_loses_reply: false,
            restore_frame_fingerprints: vec![],
            ready: true,
            reboot_during_health: false,
            version: "2011".into(),
            update_state: None,
        };
        (dir, path, plan, gateway)
    }
    #[test]
    fn lost_reboot_response_still_requires_changed_boot_root_restore_version_and_readiness() {
        let (_dir, path, mut plan, mut gateway) = transaction(true);
        install_prepared(&mut gateway, &mut plan, &path, Some(b"authorization")).unwrap();
        finish(
            &mut gateway,
            &mut plan,
            &path,
            Some(b"recovery frame"),
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Complete);
        assert_eq!(
            gateway.events,
            [
                "stop",
                &format!("install:{ID}:2023"),
                "reboot",
                "stop",
                "restore",
                "health"
            ]
        );
        assert_eq!(plan.after_boot.as_deref(), Some("new-boot"));
    }
    #[test]
    fn invalid_preflight_or_changed_identity_prevents_stopping_and_flashing() {
        let (_dir, path, mut plan, mut gateway) = transaction(true);
        gateway.preflight_ok = false;
        assert!(install_prepared(&mut gateway, &mut plan, &path, Some(b"invalid")).is_err());
        assert!(gateway.events.is_empty());
        gateway.preflight_ok = true;
        gateway.identity.boot = "another-boot".into();
        assert!(install_prepared(&mut gateway, &mut plan, &path, Some(b"valid")).is_err());
        assert!(gateway.events.is_empty());
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Prepared);
    }
    #[test]
    fn unsupported_installer_never_stops_the_gateway() {
        let (_dir, path, mut plan, mut gateway) = transaction(false);
        gateway.installer_ok = false;
        assert!(install_prepared(&mut gateway, &mut plan, &path, None).is_err());
        assert!(gateway.events.is_empty());
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Prepared);
    }

    #[test]
    fn a_second_preflight_refusal_after_stop_never_flashes_firmware() {
        let (_dir, path, mut plan, mut gateway) = transaction(true);
        gateway.preflight_fail_at = Some(2);

        assert!(install_prepared(&mut gateway, &mut plan, &path, Some(b"authorization")).is_err());

        assert_eq!(gateway.preflight_calls, 2);
        assert_eq!(gateway.events, ["stop"]);
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Installing);
        assert!(install_prepared(&mut gateway, &mut plan, &path, Some(b"authorization")).is_err());
        assert_eq!(
            gateway.events,
            ["stop"],
            "an ambiguous phase is never retried automatically"
        );
    }

    #[test]
    fn a_service_stop_failure_never_starts_the_firmware_install() {
        let (_dir, path, mut plan, mut gateway) = transaction(false);
        gateway.stop_ok = false;

        assert!(install_prepared(&mut gateway, &mut plan, &path, None).is_err());

        assert_eq!(gateway.events, ["stop"]);
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Installing);
        assert!(matches!(
            finish(
                &mut gateway,
                &mut plan,
                &path,
                None,
                Duration::ZERO,
            ),
            Err(error) if matches!(
                error.downcast_ref::<FirmwareError>(),
                Some(FirmwareError::InstallationUncertain)
            )
        ));
        assert_eq!(gateway.events, ["stop"]);
    }

    #[test]
    fn an_unobserved_reboot_is_not_requested_again_on_resume() {
        let (_dir, path, mut plan, mut gateway) = transaction(false);
        plan.phase = Phase::Installed;
        gateway.reboot_applies = false;

        assert!(matches!(
            finish(
                &mut gateway,
                &mut plan,
                &path,
                None,
                Duration::ZERO,
            ),
            Err(error) if error.downcast_ref::<FirmwareError>().is_some_and(|error| matches!(error, FirmwareError::GatewayUnavailable))
        ));
        assert_eq!(load_plan(&path).unwrap().phase, Phase::RebootRequested);
        assert_eq!(gateway.events, ["reboot"]);

        assert!(!try_finish(&mut gateway, &mut plan, &path, None)
            .expect("the unchanged boot is not a completed update"));
        assert_eq!(load_plan(&path).unwrap().phase, Phase::RebootRequested);
        assert!(plan.after_boot.is_none());
        assert_eq!(gateway.events, ["reboot"]);

        assert!(matches!(
            finish(
                &mut gateway,
                &mut plan,
                &path,
                None,
                Duration::ZERO,
            ),
            Err(error) if error.downcast_ref::<FirmwareError>().is_some_and(|error| matches!(error, FirmwareError::GatewayUnavailable))
        ));
        assert_eq!(
            gateway.events,
            ["reboot"],
            "resume observes the saved intent and does not reboot twice"
        );
        assert_eq!(load_plan(&path).unwrap().phase, Phase::RebootRequested);
    }
    #[test]
    fn pending_or_failed_firmware_never_receives_a_recovery_secret() {
        for state in [1, 3, 4, 5, 6, 99] {
            let (_dir, path, mut plan, mut gateway) = transaction(true);
            plan.phase = Phase::RebootRequested;
            gateway.identity.boot = "new-boot".into();
            gateway.version = "2023".into();
            gateway.update_state = Some(state);
            assert!(try_finish(&mut gateway, &mut plan, &path, Some(b"frame")).is_err());
            assert!(gateway.events.is_empty());
            assert_ne!(plan.phase, Phase::Complete);
        }
        let (_dir, path, mut plan, mut gateway) = transaction(true);
        plan.phase = Phase::RebootRequested;
        gateway.identity.boot = "new-boot".into();
        gateway.version = "2023".into();
        gateway.update_state = Some(2);
        assert!(try_finish(&mut gateway, &mut plan, &path, Some(b"frame")).unwrap());
    }
    #[test]
    fn ambiguous_installation_is_durable_and_never_automatically_retried() {
        let (_dir, path, mut plan, mut gateway) = transaction(false);
        gateway.install_ok = false;
        assert!(install_prepared(&mut gateway, &mut plan, &path, None).is_err());
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Installing);
        let events = gateway.events.clone();
        assert!(install_prepared(&mut gateway, &mut plan, &path, None).is_err());
        assert!(finish(&mut gateway, &mut plan, &path, None, Duration::from_secs(1)).is_err());
        assert_eq!(gateway.events, events);
    }
    #[test]
    fn recovery_and_readiness_errors_remain_resumable_without_reinstall_or_reboot() {
        let (_dir, path, mut plan, mut gateway) = transaction(true);
        plan.phase = Phase::RebootRequested;
        gateway.identity.boot = "new-boot".into();
        gateway.version = "2023".into();
        gateway.restore_ok = false;
        assert!(try_finish(&mut gateway, &mut plan, &path, Some(b"frame")).is_err());
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Restoring);
        gateway.restore_ok = true;
        gateway.ready = false;
        assert!(try_finish(&mut gateway, &mut plan, &path, Some(b"frame")).is_err());
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Verifying);
        gateway.ready = true;
        assert!(try_finish(&mut gateway, &mut plan, &path, Some(b"frame")).unwrap());
        assert!(!gateway
            .events
            .iter()
            .any(|event| event.starts_with("install") || event == "reboot"));
    }

    #[test]
    fn an_applied_restore_with_a_lost_reply_retries_the_same_frame() {
        let (_dir, path, mut plan, mut gateway) = transaction(true);
        plan.phase = Phase::RebootRequested;
        gateway.identity.boot = "new-boot".into();
        gateway.version = "2023".into();
        gateway.restore_applies_then_loses_reply = true;
        let frame = b"opaque recovery frame";

        assert!(try_finish(&mut gateway, &mut plan, &path, Some(frame)).is_err());
        assert!(gateway.restore_applied);
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Restoring);
        assert!(try_finish(&mut gateway, &mut plan, &path, Some(frame)).unwrap());

        assert_eq!(gateway.restore_frame_fingerprints.len(), 2);
        assert!(
            gateway.restore_frame_fingerprints[0].matches(&gateway.restore_frame_fingerprints[1])
        );
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Complete);
        assert!(!gateway
            .events
            .iter()
            .any(|event| event.starts_with("install") || event == "reboot"));
    }

    #[test]
    fn a_gateway_reboot_during_readiness_cannot_complete_the_plan() {
        let (_dir, path, mut plan, mut gateway) = transaction(false);
        plan.phase = Phase::RebootRequested;
        gateway.identity.boot = "new-boot".into();
        gateway.version = "2023".into();
        gateway.reboot_during_health = true;

        assert!(try_finish(&mut gateway, &mut plan, &path, None).is_err());

        assert_eq!(gateway.events, ["health"]);
        assert_eq!(load_plan(&path).unwrap().phase, Phase::Verifying);
        assert_ne!(plan.phase, Phase::Complete);
    }
    #[test]
    fn old_boot_wrong_machine_and_wrong_version_never_report_success() {
        let (_dir, path, mut plan, mut gateway) = transaction(false);
        plan.phase = Phase::RebootRequested;
        assert!(!try_finish(&mut gateway, &mut plan, &path, None).unwrap());
        assert!(gateway.events.is_empty());
        gateway.identity.machine = "other gateway".into();
        assert!(try_finish(&mut gateway, &mut plan, &path, None).is_err());
        assert!(gateway.events.is_empty());
        gateway.identity.machine = plan.before.machine.clone();
        gateway.identity.boot = "new-boot".into();
        assert!(try_finish(&mut gateway, &mut plan, &path, None).is_err());
        assert_ne!(plan.phase, Phase::Complete);
        assert!(!gateway.events.contains(&"health".into()));
        assert!(!gateway.events.contains(&"restore".into()));
    }
    #[cfg(target_os = "linux")]
    #[test]
    fn plan_lock_is_exclusive_and_released_and_journal_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let (_dir, path, _plan, _gateway) = transaction(false);
        let lock = PlanLock::acquire(&path).unwrap();
        assert!(PlanLock::acquire(&path).is_err());
        drop(lock);
        assert!(PlanLock::acquire(&path).is_ok());
        assert_eq!(
            std::fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    /// Run the real SSH adapter against a synthetic executable in an isolated
    /// test process. PATH is child-local, so unrelated tests never see the shim.
    #[test]
    fn ssh_gateway_adapter_uses_a_fake_ssh_process_without_putting_input_in_arguments() {
        const CHILD: &str = "HELIOS_TEST_SSH_ADAPTER_CHILD";
        if std::env::var_os(CHILD).is_none() {
            use std::os::unix::fs::PermissionsExt as _;

            let directory = tempfile::tempdir().expect("temporary SSH fixture");
            let bin = directory.path().join("bin");
            std::fs::create_dir(&bin).expect("fake bin directory");
            let executable = bin.join("ssh");
            std::fs::write(
                &executable,
                r##"#!/bin/sh
set -eu
printf '%s\n' "$@" > "$HELIOS_TEST_SSH_ARGS"
remote=''
for arg in "$@"; do remote=$arg; done
/bin/cat > "$HELIOS_TEST_SSH_STDIN"
mode="${HELIOS_TEST_SSH_MODE:-success}"
if [ "$mode" = "ssh-failure" ]; then printf 'denied \033[31m\n' >&2; exit 17; fi
case "$remote" in
  *"cat /etc/machine-id /proc/sys/kernel/random/boot_id"*)
    if [ "$mode" = "identity-invalid" ]; then printf 'bad\nboot\n'; else printf 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n12345678-1234-1234-1234-123456789abc\n'; fi ;;
  *"fwupdmgr --version --json"*)
    if [ "$mode" = "installer-old" ]; then printf '%s\n' '{"Versions":[{"Type":"compile","AppstreamId":"org.freedesktop.fwupd","Version":"2.0.19"}]}' ; else printf '%s\n' '{"Versions":[{"Type":"compile","AppstreamId":"org.freedesktop.fwupd","Version":"2.0.20"}]}' ; fi ;;
  *"sealing-status"*)
    case "$mode" in
      sealing-unknown) printf 'maybe\n' ;;
      sealing-disabled) printf 'disabled\n' ;;
      *) printf 'enabled\n' ;;
    esac ;;
  *"firmware-preflight"*)
    if [ "$mode" = "preflight-ambiguous" ]; then printf 'almost-ready\n'; else printf 'ready\n'; fi ;;
  *"export-firmware"*) /bin/cat "$HELIOS_TEST_SSH_BACKUP" ;;
  *"fwupdmgr get-updates --json"*|*"fwupdmgr get-devices --json"*)
    if [ "$mode" = "inventory-malformed" ]; then printf '{broken'; else printf '%s\n' '{"Devices":[{"DeviceId":"5bc922b7bd1adb5b6f99592611404036bd9f42d0","Name":"UEFI DBX","Version":"2022","Releases":[{"Version":"2023"}]}]}'; fi ;;
  *"fwupdmgr install"*) printf 'installed\n' ;;
  *"restore-firmware"*)
    case "$mode" in
      restore-ambiguous) printf 'unknown\n' ;;
      restore-unchanged) printf 'unchanged\n' ;;
      *) printf 'restored\n' ;;
    esac ;;
  *"cat /run/helios/ready"*)
    case "$mode" in
      readiness-pid-mismatch) printf 'pid=4243\nmode_reel=true\nfirewall_enforced=true\n' ;;
      readiness-not-enforced) printf 'pid=4242\nmode_reel=true\nfirewall_enforced=false\n' ;;
      *) printf 'pid=4242\nmode_reel=true\nfirewall_enforced=true\n' ;;
    esac ;;
  *"systemctl show --property=MainPID --value heliosd.service"*) printf '4242\n' ;;
  *"systemctl start heliosd.service"*|*"systemctl stop heliosd.service"*|*"systemctl reboot"*|*"systemctl is-active --quiet heliosd.service"*) : ;;
  *) printf 'unexpected remote command\n' >&2; exit 19 ;;
esac
"##,
            )
            .expect("write fake ssh");
            let mut permissions = std::fs::metadata(&executable)
                .expect("fake ssh metadata")
                .permissions();
            permissions.set_mode(0o755);
            std::fs::set_permissions(&executable, permissions).expect("make fake ssh executable");

            let backup = FirmwareBackup {
                request: aether::sig::FirmwareRecoveryPayload {
                    version: 1,
                    sealed_blob_anchor: [1; 32],
                    secret_commitment: [2; 32],
                    device_id: ID.into(),
                    target_version: "2023".into(),
                },
                encrypted_secret: vec![3, 4, 5],
            };
            let backup_path = directory.path().join("backup.json");
            std::fs::write(
                &backup_path,
                serde_json::to_vec(&backup).expect("backup JSON"),
            )
            .expect("write backup fixture");

            // Only the fixture directory is on PATH: if the shim is absent or
            // unusable, the child cannot fall through to a real system ssh.
            let child_path = std::env::join_paths([bin]).expect("child PATH");
            let mut child = std::process::Command::new(
                std::env::current_exe().expect("test executable"),
            )
            .args([
                "--exact",
                "firmware::tests::ssh_gateway_adapter_uses_a_fake_ssh_process_without_putting_input_in_arguments",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("PATH", child_path)
            .env("HELIOS_TEST_SSH_ARGS", directory.path().join("args.txt"))
            .env("HELIOS_TEST_SSH_STDIN", directory.path().join("stdin.bin"))
            .env("HELIOS_TEST_SSH_BACKUP", backup_path)
            .spawn()
            .expect("isolated SSH adapter test starts");
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
            loop {
                if let Some(status) = child.try_wait().expect("poll isolated test child") {
                    assert!(status.success(), "isolated SSH adapter test succeeds");
                    break;
                }
                if std::time::Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("isolated SSH adapter test exceeded 30 seconds");
                }
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            return;
        }

        let args_path = std::env::var_os("HELIOS_TEST_SSH_ARGS").expect("args trace path");
        let stdin_path = std::env::var_os("HELIOS_TEST_SSH_STDIN").expect("stdin trace path");
        let mut gateway = SshGateway::new("operator@gateway:2222").expect("valid target");
        assert!(SshGateway::new("operator@gateway;reboot").is_err());

        let identity = gateway.identity().expect("gateway identity");
        assert_eq!(identity.machine, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        assert_eq!(identity.boot, "12345678-1234-1234-1234-123456789abc");
        let args = std::fs::read_to_string(&args_path).expect("identity command trace");
        assert!(args.contains("-T\n-o\nBatchMode=yes"));
        assert!(args.contains("StrictHostKeyChecking=yes"));
        assert!(args.contains("-p\n2222"));
        assert!(args.contains("operator@gateway"));
        assert!(args.contains("timeout --signal=TERM 30s sh -c"));
        assert!(std::fs::read(&stdin_path).expect("empty input").is_empty());

        gateway.check_installer().expect("supported fwupd version");
        std::env::set_var("HELIOS_TEST_SSH_MODE", "installer-old");
        assert!(gateway.check_installer().is_err());
        std::env::set_var("HELIOS_TEST_SSH_MODE", "success");
        assert!(gateway.sealing().expect("sealed TPM posture"));
        std::env::set_var("HELIOS_TEST_SSH_MODE", "sealing-disabled");
        assert!(!gateway.sealing().expect("disabled TPM posture"));
        std::env::set_var("HELIOS_TEST_SSH_MODE", "success");
        let devices = gateway.inventory(true).expect("updates inventory");
        assert_eq!(devices.len(), 1);
        assert_eq!(devices[0].id, ID);
        assert_eq!(devices[0].releases[0].version, "2023");
        assert_eq!(gateway.inventory(false).expect("full inventory").len(), 1);

        let backup = gateway
            .export(&[8; 32], ID, "2023")
            .expect("encrypted firmware backup");
        assert_eq!(backup.request.device_id, ID);
        assert_eq!(backup.encrypted_secret, [3, 4, 5]);

        let auth = b"synthetic-auth-input";
        gateway.preflight(auth).expect("exact preflight response");
        assert_eq!(std::fs::read(&stdin_path).expect("preflight stdin"), auth);
        let args = std::fs::read_to_string(&args_path).expect("preflight command trace");
        assert!(!args.contains(std::str::from_utf8(auth).expect("auth marker")));
        assert!(args.contains("firmware-preflight"));

        gateway.stop().expect("stop gateway service");
        gateway
            .install(ID, "2023")
            .expect("pinned firmware installation");
        let args = std::fs::read_to_string(&args_path).expect("install command trace");
        let remote = args.lines().last().expect("remote install command");
        assert!(remote.starts_with("sudo -n fwupdmgr install"));
        assert!(remote.contains(ID));
        assert!(remote.contains("'2023' --assume-yes --no-reboot-check"));
        assert!(!remote.contains("timeout --signal=TERM"));
        gateway.reboot().expect("gateway reboot command");

        let frame = b"synthetic-restore-frame";
        gateway.restore(frame).expect("restored response");
        assert_eq!(std::fs::read(&stdin_path).expect("restore stdin"), frame);
        let args = std::fs::read_to_string(&args_path).expect("restore command trace");
        assert!(!args.contains(std::str::from_utf8(frame).expect("frame marker")));
        assert!(args.contains("restore-firmware"));
        std::env::set_var("HELIOS_TEST_SSH_MODE", "restore-unchanged");
        gateway
            .restore(frame)
            .expect("idempotent unchanged response");

        std::env::set_var("HELIOS_TEST_SSH_MODE", "success");
        gateway
            .start_and_check()
            .expect("active service and real enforced readiness");
        std::env::set_var("HELIOS_TEST_SSH_MODE", "readiness-pid-mismatch");
        assert!(gateway
            .start_and_check()
            .expect_err("readiness from another process refused")
            .to_string()
            .contains("another service process"));
        std::env::set_var("HELIOS_TEST_SSH_MODE", "readiness-not-enforced");
        assert!(gateway
            .start_and_check()
            .expect_err("non-enforced readiness refused")
            .to_string()
            .contains("real, enforced readiness"));

        std::env::set_var("HELIOS_TEST_SSH_MODE", "sealing-unknown");
        assert!(gateway.sealing().is_err());
        std::env::set_var("HELIOS_TEST_SSH_MODE", "preflight-ambiguous");
        assert!(gateway.preflight(auth).is_err());
        std::env::set_var("HELIOS_TEST_SSH_MODE", "restore-ambiguous");
        assert!(gateway.restore(frame).is_err());
        std::env::set_var("HELIOS_TEST_SSH_MODE", "inventory-malformed");
        assert!(gateway.inventory(true).is_err());
        std::env::set_var("HELIOS_TEST_SSH_MODE", "identity-invalid");
        assert!(gateway.identity().is_err());
        std::env::set_var("HELIOS_TEST_SSH_MODE", "ssh-failure");
        let error = gateway
            .stop()
            .expect_err("non-zero ssh status surfaced")
            .to_string();
        assert!(error.contains("gateway operation failed"));
        assert!(
            !error.contains('\u{1b}'),
            "terminal control bytes are removed"
        );
    }
}
