//! Exercise the real line editor and command loop on an isolated Linux terminal.

use std::{
    fs::File,
    io::{self, Read, Write},
    os::fd::{AsRawFd, FromRawFd},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::Result;

use super::{run, Api};

const SHELL_TEST: &str = "HELIOS_TEST_SHELL_ENTRY";
const NO_GATEWAY: &str = "http://127.0.0.1:0";
const DEADLINE: Duration = Duration::from_secs(10);

fn shell_command(name: &str, base: &str) -> Command {
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            &format!("interactive::shell_tests::{name}"),
            "--nocapture",
        ])
        .env(SHELL_TEST, base)
        .env("TERM", "xterm-256color")
        .env("NO_COLOR", "1")
        .env("NO_PROXY", "127.0.0.1")
        .env("no_proxy", "127.0.0.1")
        .env_remove("HELIOS_URL");
    command
}

/// Run the entry point in another process so Rustyline owns that process's
/// descriptors and signal handlers. The harness captures the actual terminal
/// output with libtest's own capture disabled.
async fn shell_child() -> Option<Result<()>> {
    let base = std::env::var(SHELL_TEST).ok()?;
    Some(run(Api::tcp(&base).expect("shell HTTP client")).await)
}

fn open_terminal() -> (File, File) {
    let mut master = -1;
    let mut slave = -1;
    let size = libc::winsize {
        ws_row: 32,
        ws_col: 100,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY: openpty writes only to the two initialized descriptors and
    // reads the initialized size. Null pointers request default settings.
    let result = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            &size,
        )
    };
    assert_eq!(
        result,
        0,
        "open pseudo-terminal: {}",
        io::Error::last_os_error()
    );
    // SAFETY: openpty returned two independently owned open descriptors.
    let terminals = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
    for terminal in [&terminals.0, &terminals.1] {
        // SAFETY: the descriptor belongs to this File and remains open.
        let result = unsafe { libc::fcntl(terminal.as_raw_fd(), libc::F_SETFD, libc::FD_CLOEXEC) };
        assert_eq!(result, 0, "set close-on-exec on pseudo-terminal");
    }
    terminals
}

struct Session {
    child: Child,
    terminal: File,
    transcript: Vec<u8>,
    read_through: usize,
}

impl Session {
    fn spawn(mut command: Command) -> Self {
        let (terminal, slave) = open_terminal();
        let child = command
            .stdin(Stdio::from(
                slave.try_clone().expect("clone input terminal"),
            ))
            .stdout(Stdio::from(
                slave.try_clone().expect("clone output terminal"),
            ))
            .stderr(Stdio::from(slave))
            .spawn()
            .expect("shell child starts");
        drop(command);
        Self {
            child,
            terminal,
            transcript: Vec::new(),
            read_through: 0,
        }
    }

    fn expect(&mut self, expected: &str) {
        let deadline = Instant::now() + DEADLINE;
        let needle = expected.as_bytes();
        loop {
            if let Some(offset) = self.transcript[self.read_through..]
                .windows(needle.len())
                .position(|window| window == needle)
            {
                self.read_through += offset + needle.len();
                return;
            }

            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                break;
            }
            let mut ready = libc::pollfd {
                fd: self.terminal.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: poll receives one initialized pollfd for the open master.
            let timeout_ms = i32::try_from(left.as_millis()).expect("bounded polling deadline");
            let polled = unsafe { libc::poll(&mut ready, 1, timeout_ms) };
            if polled < 0 && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if polled <= 0 {
                break;
            }
            let mut buffer = [0; 8192];
            match self.terminal.read(&mut buffer) {
                Ok(0) => break,
                Ok(size) => self.transcript.extend_from_slice(&buffer[..size]),
                Err(error) if error.raw_os_error() == Some(libc::EIO) => break,
                Err(error) => panic!("read pseudo-terminal: {error}"),
            }
        }
        panic!(
            "expected {expected:?} in the terminal transcript after byte {}:\n{}",
            self.read_through,
            String::from_utf8_lossy(&self.transcript)
        );
    }

    fn input(&mut self, input: &str) {
        // The next read has installed its terminal mode before displaying this
        // prompt. Waiting for it keeps test input away from the default tty mode.
        self.expect("❯ ");
        self.send(input);
    }

    fn input_at(&mut self, gateway_version: &str, input: &str) {
        self.expect("❯ ");
        self.expect(gateway_version);
        self.send(input);
    }

    fn send(&mut self, input: &str) {
        self.terminal
            .write_all(input.as_bytes())
            .expect("type into the terminal");
    }

    fn finish(mut self) {
        self.expect("test result: ok.");
        assert!(self.child.wait().expect("reap the shell child").success());
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

#[tokio::test]
async fn shell_refuses_piped_input() {
    if let Some(result) = shell_child().await {
        let error = result.expect_err("piped input is rejected");
        assert!(error
            .to_string()
            .contains("use `helios --help` for scripted commands"));
        return;
    }
    let result = shell_command("shell_refuses_piped_input", NO_GATEWAY)
        .output()
        .expect("non-interactive subprocess");
    assert!(
        result.status.success()
            && String::from_utf8_lossy(&result.stdout).contains("running 1 test"),
        "non-interactive shell child failed:\n{}\n{}",
        String::from_utf8_lossy(&result.stdout),
        String::from_utf8_lossy(&result.stderr)
    );
}

#[tokio::test]
async fn shell_refuses_an_unsupported_terminal_before_starting_the_editor() {
    if let Some(result) = shell_child().await {
        let error = result.expect_err("TERM=dumb is rejected");
        assert!(error
            .to_string()
            .contains("TERM=dumb does not support line editing/completion"));
        return;
    }
    let mut command = shell_command(
        "shell_refuses_an_unsupported_terminal_before_starting_the_editor",
        NO_GATEWAY,
    );
    command.env("TERM", "dumb");
    Session::spawn(command).finish();
}

#[tokio::test]
async fn shell_handles_help_and_invalid_builtins_without_ending_the_session() {
    if let Some(result) = shell_child().await {
        result.expect("shell exits normally");
        return;
    }
    let mut session = Session::spawn(shell_command(
        "shell_handles_help_and_invalid_builtins_without_ending_the_session",
        NO_GATEWAY,
    ));
    session.input("/help\r");
    session.expect("Usage: helios");
    session.input("peer add --name 'unfinished\r");
    session.expect("unclosed quote or trailing escape");
    session.input("/shell\r");
    session.expect("the administration shell is already open");
    session.input("/clear extra\r");
    session.expect("usage: /clear");
    session.input("/clear\r");
    session.expect("Gateway administration");
    session.input("/use\r");
    session.expect("usage: /use http://gateway:8080");
    session.input("/use ftp://gateway.invalid\r");
    session.expect("expected an HTTP(S) gateway URL");
    session.input("/exit\r");
    session.finish();
}

#[tokio::test]
async fn shell_can_clear_input_and_exit_with_two_empty_interrupts() {
    if let Some(result) = shell_child().await {
        result.expect("two empty interrupts exit normally");
        return;
    }
    let mut session = Session::spawn(shell_command(
        "shell_can_clear_input_and_exit_with_two_empty_interrupts",
        NO_GATEWAY,
    ));
    session.input("unsubmitted\x03");
    session.input("\x03");
    session.expect("Press Ctrl-C again to exit");
    session.send("\x03");
    session.finish();
}

#[tokio::test]
async fn shell_switches_gateways_and_keeps_one_off_urls_out_of_the_prompt() {
    if let Some(result) = shell_child().await {
        result.expect("shell exits normally after dispatch");
        return;
    }
    let status = |version: &str| {
        serde_json::json!({
            "state": "up",
            "version": version,
            "dry_run": true,
            "wan_ifaces": [],
            "lan_ifaces": [],
            "wg_peers": [],
            "allow_ssh_from": [],
            "peers": [],
            "wg_iface": "helios0",
            "split_tunnel_cidrs": [],
        })
        .to_string()
    };
    let (initial, initial_requests) =
        crate::tests::http_response_sequence([("200 OK", status("initial-test-gateway"))]).await;
    let (switched, switched_requests) = crate::tests::http_response_sequence([
        ("200 OK", status("selected-test-gateway")),
        ("200 OK", status("selected-test-gateway")),
        ("200 OK", "unreadable status response".to_owned()),
        ("200 OK", status("selected-test-gateway")),
    ])
    .await;
    let (one_off, one_off_requests) =
        crate::tests::http_response_sequence([("200 OK", status("one-off-test-gateway"))]).await;

    tokio::task::spawn_blocking(move || {
        let mut session = Session::spawn(shell_command(
            "shell_switches_gateways_and_keeps_one_off_urls_out_of_the_prompt",
            &initial,
        ));
        session.input_at("initial-test-gateway", &format!("/use {switched}\r"));
        session.input_at(
            "selected-test-gateway",
            &format!("--url {one_off} status\r"),
        );
        session.expect("⏺ status");
        session.expect("one-off-test-gateway");
        session.expect("✓");
        session.input_at("selected-test-gateway", "/status\r");
        session.expect("unexpected JSON response");
        session.input_at("selected-test-gateway", "/quit\r");
        session.finish();
    })
    .await
    .expect("terminal interaction");

    for (task, count) in [
        (initial_requests, 1),
        (switched_requests, 4),
        (one_off_requests, 1),
    ] {
        let requests = task.await.expect("gateway request sequence");
        assert_eq!(requests.len(), count);
        assert!(requests
            .iter()
            .all(|request| request.starts_with("GET /api/status HTTP/1.1\r\n")));
    }
}
