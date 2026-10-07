//! How the operator tool reaches the gateway API.
//!
//! On the gateway, the local administration socket (ADR-003, amendment of
//! 3 October 2026); elsewhere, the TCP API inside the tunnel.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context, Result};
use reqwest::Client;

/// A dropped TCP connection (firewall) fails here instead of hanging.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Authority used on the socket; DNS and TCP settings do not apply there.
const LOCAL_BASE: &str = "http://localhost";

pub struct Api {
    pub client: Client,
    pub base: String,
    /// Set when requests go through the local administration socket.
    pub socket: Option<PathBuf>,
}

impl Api {
    pub fn tcp(url: &str) -> Result<Self> {
        Ok(Self {
            client: Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .context("building the HTTP client")?,
            base: url.trim_end_matches('/').to_owned(),
            socket: None,
        })
    }

    /// An explicit URL always means TCP. Otherwise the local socket when it
    /// exists — and then it must pass [`check_socket`]: an untrusted socket
    /// is an error, never a silent fallback — else the in-tunnel API.
    pub fn resolve(url: Option<&str>, socket: &Path) -> Result<Self> {
        if let Some(url) = url {
            return Self::tcp(url);
        }
        match std::fs::symlink_metadata(socket) {
            Ok(_) => Self::local(socket),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                Self::tcp(aether::DEFAULT_WG_API_URL)
            }
            Err(error) => Err(error).with_context(|| format!("inspecting {}", socket.display())),
        }
    }

    #[cfg(unix)]
    fn local(socket: &Path) -> Result<Self> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let file = std::fs::symlink_metadata(socket)
            .with_context(|| format!("inspecting {}", socket.display()))?;
        let directory = socket
            .parent()
            .context("the socket path has no directory")
            .and_then(|dir| {
                std::fs::metadata(dir).with_context(|| format!("inspecting {}", dir.display()))
            })?;
        check_socket(
            file.file_type().is_socket(),
            file.uid(),
            directory.uid(),
            directory.mode(),
        )
        .with_context(|| {
            format!(
                "refusing the local administration socket {}",
                socket.display()
            )
        })?;
        Ok(Self {
            client: Client::builder()
                .unix_socket(socket)
                .build()
                .context("building the local socket client")?,
            base: LOCAL_BASE.to_owned(),
            socket: Some(socket.to_owned()),
        })
    }

    #[cfg(not(unix))]
    fn local(socket: &Path) -> Result<Self> {
        anyhow::bail!(
            "{} exists, but local sockets are not supported on this platform; use --url",
            socket.display()
        )
    }

    /// Short form for the status line.
    pub fn label(&self) -> String {
        match &self.socket {
            Some(_) => "local".to_owned(),
            None => self.base.clone(),
        }
    }

    /// Long form for the welcome panel.
    pub fn describe(&self) -> String {
        match &self.socket {
            Some(path) => format!("local socket {}", path.display()),
            None => self.base.clone(),
        }
    }
}

/// Only root can have created a root-owned socket in a directory that only
/// root can write: anyone else could otherwise stand up a fake gateway API.
fn check_socket(
    is_socket: bool,
    owner: u32,
    directory_owner: u32,
    directory_mode: u32,
) -> Result<()> {
    anyhow::ensure!(is_socket, "the path exists but is not a socket");
    anyhow::ensure!(owner == 0, "the socket is not owned by root");
    anyhow::ensure!(directory_owner == 0, "its directory is not owned by root");
    anyhow::ensure!(
        directory_mode & 0o022 == 0,
        "its directory is writable by other users"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_root_owned_socket_in_a_root_controlled_directory_is_trusted() {
        assert!(check_socket(true, 0, 0, 0o755).is_ok());
        let refusal = |case: Result<()>| format!("{:#}", case.unwrap_err());
        assert!(refusal(check_socket(false, 0, 0, 0o755)).contains("not a socket"));
        assert!(refusal(check_socket(true, 1000, 0, 0o755)).contains("not owned by root"));
        assert!(refusal(check_socket(true, 0, 1000, 0o755)).contains("directory"));
        assert!(refusal(check_socket(true, 0, 0, 0o775)).contains("writable"));
        assert!(refusal(check_socket(true, 0, 0, 0o1777)).contains("writable"));
    }

    #[test]
    fn an_explicit_url_wins_and_no_socket_means_the_tunnel_api() {
        let missing = std::path::Path::new("/nonexistent/helios/admin.sock");
        let api = Api::resolve(Some("http://gw:8080/"), missing).unwrap();
        assert_eq!(
            (api.base.as_str(), api.label()),
            ("http://gw:8080", "http://gw:8080".into())
        );
        let api = Api::resolve(None, missing).unwrap();
        assert_eq!(api.base, aether::DEFAULT_WG_API_URL);
        assert!(api.socket.is_none());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn an_untrusted_socket_is_an_error_not_a_fallback() {
        // SAFETY: plain getter of the calling process's uid.
        if unsafe { libc::getuid() } == 0 {
            return;
        }
        let dir = std::env::temp_dir().join(format!("helios-sock-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("admin.sock");
        let _listener = tokio::net::UnixListener::bind(&path).unwrap();
        let error = Api::resolve(None, &path)
            .err()
            .expect("a user-owned socket");
        assert!(
            format!("{error:#}").contains("not owned by root"),
            "{error:#}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
