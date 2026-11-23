//! Private, disposable swtpm process for ESAPI integration tests.
//!
//! Each caller owns its own process, state directory and loopback ports. The
//! helper never reads or changes process-wide environment variables and never
//! touches a hardware TPM device.

use std::process::{Child, Command, Stdio};

pub struct Swtpm {
    child: Child,
    _state: tempfile::TempDir,
    server_port: u16,
    tcti: String,
}

impl Swtpm {
    /// Starts a fresh emulator when `swtpm` is available. `Ok(None)` means the
    /// host cannot provide a local loopback listener; process/startup faults
    /// are returned so an installed but broken emulator cannot look like a
    /// skipped test.
    pub fn start() -> Result<Option<Self>, String> {
        match Command::new("swtpm").arg("--version").output() {
            Ok(output) if output.status.success() => {}
            Ok(output) => {
                return Err(format!("swtpm --version exited with {}", output.status));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(format!("checking swtpm availability: {error}")),
        }

        let mut last_startup_error = None;
        for _ in 0..8 {
            let Some((server_port, control_port)) = loopback_port_pair() else {
                return Ok(None);
            };
            let state =
                tempfile::tempdir().map_err(|error| format!("creating swtpm state: {error}"))?;
            let server = format!("type=tcp,port={server_port},bindaddr=127.0.0.1");
            let control = format!("type=tcp,port={control_port},bindaddr=127.0.0.1");
            let state_arg = format!("dir={}", state.path().display());
            let child = Command::new("swtpm")
                .args([
                    "socket",
                    "--tpm2",
                    "--tpmstate",
                    &state_arg,
                    "--server",
                    &server,
                    "--ctrl",
                    &control,
                    "--flags",
                    "not-need-init,startup-clear",
                ])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .map_err(|error| format!("starting loopback-only swtpm: {error}"))?;
            let tcti = format!("swtpm:host=127.0.0.1,port={server_port}");
            let mut simulator = Self {
                child,
                _state: state,
                server_port,
                tcti,
            };
            match simulator.wait_until_ready() {
                Ok(()) => return Ok(Some(simulator)),
                Err(error) => last_startup_error = Some(error),
            }
            drop(simulator);
        }
        Err(last_startup_error.unwrap_or_else(|| "could not start swtpm".into()))
    }

    pub fn tcti(&self) -> &str {
        &self.tcti
    }

    fn wait_until_ready(&mut self) -> Result<(), String> {
        use std::net::TcpStream;
        use std::time::{Duration, Instant};

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            if let Some(status) = self
                .child
                .try_wait()
                .map_err(|error| format!("checking swtpm process: {error}"))?
            {
                return Err(format!("swtpm exited before readiness: {status}"));
            }
            if TcpStream::connect(("127.0.0.1", self.server_port)).is_ok() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        Err("swtpm did not open its loopback data port within two seconds".into())
    }
}

impl Drop for Swtpm {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn loopback_port_pair() -> Option<(u16, u16)> {
    use std::net::TcpListener;

    for _ in 0..8 {
        let server = TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let server_port = server.local_addr().ok()?.port();
        if server_port == u16::MAX {
            continue;
        }
        let control_port = server_port + 1;
        let control = match TcpListener::bind(("127.0.0.1", control_port)) {
            Ok(listener) => listener,
            Err(_) => continue,
        };
        drop(control);
        drop(server);
        return Some((server_port, control_port));
    }
    None
}
