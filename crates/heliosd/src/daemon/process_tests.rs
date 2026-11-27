use super::{run_with_settings, NetworkConfig, TpmSettings};
use crate::orchestrator::FirewallMode;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const TEST_API_BIND: &str = "HELIOS_TEST_DAEMON_API_BIND";
const TEST_PROC: &str = "daemon::process_tests::run_simulated_daemon";

struct RunningDaemon(Child);

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

fn wait_for(log: &Path, description: &str, mut is_ready: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !is_ready() {
        assert!(
            Instant::now() < deadline,
            "{description}\n{}",
            std::fs::read_to_string(log).unwrap_or_default()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn catches_sigterm(pid: u32) -> bool {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
    let caught = status
        .lines()
        .find_map(|line| line.strip_prefix("SigCgt:"))
        .and_then(|mask| u64::from_str_radix(mask.trim(), 16).ok())
        .unwrap_or(0);
    caught & (1 << (libc::SIGTERM - 1)) != 0
}

fn get_api_json(address: SocketAddr, route: &str) -> serde_json::Value {
    let mut connection = TcpStream::connect_timeout(&address, Duration::from_secs(2))
        .expect("connect to the simulated gateway");
    connection
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("bound HTTP response wait");
    write!(
        connection,
        "GET {route} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    )
    .expect("request gateway state");
    let mut response = String::new();
    connection
        .read_to_string(&mut response)
        .expect("read gateway response");
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    let (_, body) = response
        .split_once("\r\n\r\n")
        .expect("separate HTTP headers");
    serde_json::from_str(body).expect("decode gateway response")
}

fn replace_network_config(config: &Path, content: &str) {
    let candidate = config.with_extension("tmp");
    std::fs::write(&candidate, content).expect("write candidate configuration");
    std::fs::rename(candidate, config).expect("replace the fixture configuration atomically");
}

#[test]
fn daemon_recovers_its_listener_reloads_configuration_and_stops_on_sigterm() {
    let directory = tempfile::tempdir().expect("isolated daemon directory");
    let root = directory.path();
    let network = root.join("network.toml");
    let marker = root.join("ready");
    let log = root.join("daemon.log");
    let key = aether::wg::generate_keypair().expect("generate disposable WireGuard identity");
    std::fs::write(
        &network,
        format!(
            "wan_iface = \"lo\"\nwg_private_key = \"{}\"\n",
            key.private_key.expose()
        ),
    )
    .expect("write simulation config");

    let holder = TcpListener::bind("127.0.0.1:0").expect("reserve a loopback port");
    let address = holder.local_addr().expect("port chosen by the OS");
    let log_output = std::fs::File::create(&log).expect("open daemon log");
    let mut daemon = RunningDaemon(
        Command::new(std::env::current_exe().expect("daemon test executable"))
            .args(["--exact", TEST_PROC, "--nocapture"])
            .env(TEST_API_BIND, address.to_string())
            .env("HELIOS_NETWORK_CONFIG", &network)
            .env("HELIOS_IDENTITY_DIR", root)
            .env("HELIOS_READY_PATH", &marker)
            .env(
                "HELIOS_CERTIFICATE_REGISTRY",
                root.join("certificates.json"),
            )
            .env("HELIOS_UPDATE_STAGING", root.join("updates"))
            .env("HELIOS_UPDATE_CHANNEL", "daemon-lifecycle-test")
            .stdout(Stdio::from(
                log_output.try_clone().expect("duplicate log handle"),
            ))
            .stderr(Stdio::from(log_output))
            .spawn()
            .expect("start the isolated daemon"),
    );

    wait_for(&log, "daemon did not retry the busy API port", || {
        std::fs::read_to_string(&log)
            .unwrap_or_default()
            .contains("API server unavailable (attempt 1/")
    });
    assert!(!marker.exists(), "readiness must wait for the API bind");
    drop(holder);

    wait_for(&log, "daemon did not become ready", || marker.exists());
    let readiness = std::fs::read_to_string(&marker).expect("read readiness marker");
    assert!(readiness.contains("mode_reel=false\n"), "{readiness}");
    assert!(
        readiness.contains("firewall_enforced=false\n"),
        "{readiness}"
    );

    let status = get_api_json(address, "/api/status");
    assert_eq!(status["dry_run"], true);
    assert_eq!(status["split_tunnel_cidrs"], serde_json::json!([]));

    replace_network_config(
        &network,
        "wan_iface = \"lo\"\nsplit_tunnel_cidrs = [\"10.20.0.0/16\"]\n",
    );
    wait_for(&log, "gateway did not apply the file reload", || {
        get_api_json(address, "/api/status")["split_tunnel_cidrs"]
            == serde_json::json!(["10.20.0.0/16"])
    });
    let reloaded = get_api_json(address, "/api/network");
    assert_eq!(reloaded["wg_public_key"], key.public_key.as_str());
    assert!(reloaded.get("wg_private_key").is_none());

    replace_network_config(
        &network,
        "wan_iface = \"lo\"\nwg_address_v6 = \"fd3c:91a2:7e04::1/64\"\nsplit_tunnel_cidrs = [\"10.30.0.0/16\"]\n",
    );
    wait_for(
        &log,
        "gateway did not report the restart-only change",
        || {
            std::fs::read_to_string(&log)
                .unwrap_or_default()
                .contains("changed on disk but cannot be applied live")
        },
    );
    let following = get_api_json(address, "/api/network");
    assert_eq!(
        following["split_tunnel_cidrs"],
        serde_json::json!(["10.20.0.0/16"])
    );
    assert!(following["wg_address_v6"].is_null());
    assert_eq!(following["wg_public_key"], key.public_key.as_str());

    let pid = daemon.0.id();
    wait_for(&log, "daemon did not register SIGTERM", || {
        catches_sigterm(pid)
    });
    // SAFETY: the running child belongs to this test and we send it SIGTERM.
    assert_eq!(unsafe { libc::kill(pid as libc::pid_t, libc::SIGTERM) }, 0);
    wait_for(&log, "daemon did not shut down", || {
        daemon.0.try_wait().expect("poll daemon exit").is_some()
    });
    assert!(daemon.0.wait().expect("collect exit status").success());
    let diagnostics = std::fs::read_to_string(&log).expect("read daemon log after exit");
    assert!(
        diagnostics.contains("shutdown requested: kill-switch maintained"),
        "{diagnostics}"
    );
    assert!(TcpStream::connect_timeout(&address, Duration::from_millis(200)).is_err());
}

#[tokio::test]
async fn run_simulated_daemon() {
    let Ok(api_bind) = std::env::var(TEST_API_BIND) else {
        return;
    };
    let api_bind: SocketAddr = api_bind.parse().expect("isolated API address");
    assert!(api_bind.ip().is_loopback());
    tracing_subscriber::fmt()
        .with_ansi(false)
        .with_max_level(tracing::Level::INFO)
        .init();

    let network = NetworkConfig::load().expect("isolated network configuration");
    let network_path = PathBuf::from(
        std::env::var_os("HELIOS_NETWORK_CONFIG").expect("isolated configuration path"),
    );
    let root = network_path.parent().expect("isolated daemon directory");
    let settings = TpmSettings {
        enabled: false,
        simulated_counter_path: root.join("tpm-counter").display().to_string(),
        counter_status_path: root.join("counter-status.json").display().to_string(),
        ..TpmSettings::default()
    };
    run_with_settings(network, true, FirewallMode::Enforced, settings, |_, _| {
        Ok((
            api_bind,
            "127.0.0.1:0".parse().expect("loopback speedtest address"),
        ))
    })
    .await
    .expect("simulated daemon run");
}
