//! One writer of the state volume at a time (§5.9).
//!
//! The service owns `registry.json` in memory from the moment it starts and
//! never reads it again; a second process writing the same file meanwhile is a
//! write the service silently overwrites at its next save — the corruption
//! `scripts/deploy.sh` stops the service to avoid. A convention kept by a
//! script is replaced here by an exclusive lock on a file of the volume:
//! `astra run` holds it for its whole life, and a console write that obtains
//! it knows no service is running.
//!
//! An advisory lock, taken by `flock(2)` through [`std::fs::File::try_lock`]:
//! it is released by the kernel when the process ends, however it ends, so a
//! crashed service never leaves the volume locked behind it.

use std::fs::{File, OpenOptions, TryLockError};
use std::path::Path;

/// The file of the state volume whose lock is the right to write it.
///
/// Empty; only its lock means anything.
pub const VOLUME_LOCK_FILE: &str = "astra.lock";

/// The exclusive lock on a state volume, held until dropped.
#[derive(Debug)]
pub struct VolumeLock {
    /// Kept open: closing the file is what releases the lock.
    _file: File,
}

impl VolumeLock {
    /// Takes the volume's lock, or reports that another process holds it.
    ///
    /// `Ok(None)` is the answer «held elsewhere», and not an error: a console
    /// write that finds the lock taken goes to the running service instead.
    /// Never waits.
    pub fn try_acquire(state_dir: &Path) -> std::io::Result<Option<Self>> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(state_dir.join(VOLUME_LOCK_FILE))?;
        match file.try_lock() {
            Ok(()) => Ok(Some(Self { _file: file })),
            Err(TryLockError::WouldBlock) => Ok(None),
            Err(TryLockError::Error(error)) => Err(error),
        }
    }
}

/// One writer of the volume's own files inside the service at a time.
///
/// The cross-process half is [`VolumeLock`]; this is the in-process half. The
/// chain plan is read, changed and written back around a number of `.await`s,
/// and the delegation key files are named by epoch: two requests interleaving
/// would each act on a state the other is changing. Neither the registry nor
/// the operation store may be taken to hold this, and neither is held under
/// it across an `.await`.
#[derive(Debug, Default)]
pub struct VolumeWrites(tokio::sync::Mutex<()>);

/// Proof that [`VolumeWrites`] is held, for the functions that require it.
///
/// Taken as a parameter rather than stated in a comment, so that calling one
/// of them without the gate is a compile error.
#[derive(Debug)]
pub struct VolumeWritesHeld<'a> {
    _guard: tokio::sync::MutexGuard<'a, ()>,
}

impl VolumeWrites {
    pub fn new() -> Self {
        Self::default()
    }

    /// Waits for the gate, and holds it until the proof is dropped.
    pub async fn lock(&self) -> VolumeWritesHeld<'_> {
        VolumeWritesHeld {
            _guard: self.0.lock().await,
        }
    }
}
