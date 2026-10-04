//! Local administration over a Unix socket (ADR-003, amendment of
//! 3 October 2026).
//!
//! The kernel, not the network, authenticates the caller: each connection's
//! peer credentials are read before the first request, and only root or a
//! member of [`LOCAL_ADMIN_GROUP`] is served. Every request on an accepted
//! connection then carries a [`LocalAdmin`] marker that only this listener
//! inserts — no header or body can produce it, and the TCP listener never
//! does.

use std::{
    ffi::CString,
    io,
    mem::size_of,
    os::{
        fd::{AsRawFd, RawFd},
        unix::fs::{FileTypeExt, PermissionsExt},
    },
    path::Path,
    time::Duration,
};

use anyhow::Context;
use axum::Extension;
use hyper_util::{rt::TokioIo, service::TowerToHyperService};
use tokio::net::{UnixListener, UnixStream};

use crate::AppState;

/// Group whose members may administer Helios locally. It already grants
/// root through `sudo`, so the socket adds no privilege.
pub const LOCAL_ADMIN_GROUP: &str = "sudo";

/// Socket path inside the service's root-owned `RuntimeDirectory`.
pub const LOCAL_ADMIN_SOCKET: &str = "/run/helios/admin.sock";

/// Identity of a caller accepted on the local socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalAdmin {
    pub uid: u32,
    pub pid: i32,
}

/// Which local callers the socket serves.
#[derive(Debug, Clone, Copy)]
pub struct AdminPolicy {
    /// `None` when the system has no [`LOCAL_ADMIN_GROUP`]: root only.
    pub admin_gid: Option<u32>,
}

impl AdminPolicy {
    /// Root, plus the members of [`LOCAL_ADMIN_GROUP`] if the system has it.
    pub fn system() -> io::Result<Self> {
        Ok(Self {
            admin_gid: group_id(LOCAL_ADMIN_GROUP)?,
        })
    }

    pub fn admits(&self, uid: u32, groups: &[u32]) -> bool {
        uid == 0 || self.admin_gid.is_some_and(|gid| groups.contains(&gid))
    }
}

/// Serves the API router on `path` until the listener fails.
pub async fn serve_local(state: AppState, path: &Path, policy: AdminPolicy) -> anyhow::Result<()> {
    let listener = bind(path)?;
    tracing::info!(socket = %path.display(), "local administration socket ready");
    let app = crate::router(state);
    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(error) => {
                // Transient (descriptor exhaustion): keep serving.
                tracing::warn!("local administration socket: accept failed: {error}");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let credentials = match peer_credentials(&stream) {
            Ok(credentials) => credentials,
            Err(error) => {
                tracing::warn!(
                    "local administration refused: unreadable peer credentials: {error}"
                );
                continue;
            }
        };
        if !policy.admits(credentials.uid, &credentials.groups) {
            tracing::warn!(
                uid = credentials.uid,
                pid = credentials.pid,
                "local administration refused: caller is neither root nor a member of `{LOCAL_ADMIN_GROUP}`"
            );
            continue;
        }
        let marker = LocalAdmin {
            uid: credentials.uid,
            pid: credentials.pid,
        };
        let service = TowerToHyperService::new(app.clone().layer(Extension(marker)));
        tokio::spawn(async move {
            if let Err(error) = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .with_upgrades()
                .await
            {
                tracing::debug!("local administration connection ended: {error}");
            }
        });
    }
}

/// Replaces only a stale socket, never another kind of file.
fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)
            .with_context(|| format!("removing the stale socket {}", path.display()))?,
        Ok(_) => anyhow::bail!(
            "{} exists and is not a socket: refusing to replace it",
            path.display()
        ),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).with_context(|| format!("inspecting {}", path.display())),
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    // The service umask creates it 0600; authorization is the credential
    // check above, so every local user must be able to reach that check.
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666))
        .with_context(|| format!("opening {} to the credential check", path.display()))?;
    Ok(listener)
}

struct Credentials {
    uid: u32,
    pid: i32,
    groups: Vec<u32>,
}

fn peer_credentials(stream: &UnixStream) -> io::Result<Credentials> {
    let credentials = stream.peer_cred()?;
    let mut groups = peer_groups(stream.as_raw_fd())?;
    groups.push(credentials.gid());
    Ok(Credentials {
        uid: credentials.uid(),
        pid: credentials.pid().unwrap_or(0),
        groups,
    })
}

/// Supplementary groups of the peer process, as the kernel recorded them at
/// `connect` (`SO_PEERGROUPS`), rather than a later `/etc/group` lookup.
fn peer_groups(fd: RawFd) -> io::Result<Vec<u32>> {
    let mut groups: Vec<libc::gid_t> = vec![0; 64];
    loop {
        let mut length = (groups.len() * size_of::<libc::gid_t>()) as libc::socklen_t;
        // SAFETY: `groups` is valid for `length` bytes, and the kernel writes
        // at most `length` bytes, reporting the size it needed on ERANGE.
        let result = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_PEERGROUPS,
                groups.as_mut_ptr().cast(),
                &mut length,
            )
        };
        let needed = length as usize / size_of::<libc::gid_t>();
        if result == 0 {
            groups.truncate(needed);
            return Ok(groups);
        }
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ERANGE) || needed <= groups.len() {
            return Err(error);
        }
        groups.resize(needed, 0);
    }
}

fn group_id(name: &str) -> io::Result<Option<u32>> {
    let name =
        CString::new(name).map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let mut buffer: Vec<libc::c_char> = vec![0; 4096];
    loop {
        // SAFETY: zeroed is a valid `group`; getgrnam_r fills it and points
        // its strings into `buffer`, which outlives the read of `gr_gid`.
        let mut group: libc::group = unsafe { std::mem::zeroed() };
        let mut found: *mut libc::group = std::ptr::null_mut();
        let result = unsafe {
            libc::getgrnam_r(
                name.as_ptr(),
                &mut group,
                buffer.as_mut_ptr(),
                buffer.len(),
                &mut found,
            )
        };
        match result {
            0 => return Ok((!found.is_null()).then_some(group.gr_gid)),
            libc::ERANGE if buffer.len() < 1 << 20 => buffer.resize(buffer.len() * 2, 0),
            error => return Err(io::Error::from_raw_os_error(error)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_and_admin_group_members_only() {
        let policy = AdminPolicy {
            admin_gid: Some(27),
        };
        assert!(policy.admits(0, &[]));
        assert!(policy.admits(1000, &[1000, 27]));
        assert!(!policy.admits(1000, &[1000, 4]));
        let root_only = AdminPolicy { admin_gid: None };
        assert!(root_only.admits(0, &[]));
        assert!(!root_only.admits(1000, &[27]));
    }

    #[test]
    fn an_absent_group_is_not_an_error() {
        assert_eq!(group_id("helios-no-such-group").unwrap(), None);
    }
}
