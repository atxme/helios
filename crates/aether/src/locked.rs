//! Secret buffer kept out of swap, and wiped on drop
//! ([ADR-006](../../../docs/adr/ADR-006-SECRETS-AU-REPOS.md) §5).
//!
//! # What locking buys, and what it does not
//!
//! `zeroize` wipes a buffer **when the process still has it**. It does nothing
//! about a copy the kernel already wrote to swap or to the hibernation file:
//! those bytes outlive the process, and no user-space code can reach them.
//! `mlock` and `VirtualLock` are what stop that copy from being made.
//!
//! They are **not** a boundary against a debugger, an injection, or malware
//! running as the same account — ADR-006's T9 and T10 stay exactly where they
//! were. A locked page is still readable by anything that can read the process.
//!
//! # Why a fixed-capacity buffer
//!
//! A `String` or a `Vec` that grows reallocates: the old block is copied into
//! the new one and freed **unwiped** by the allocator, and the lock applied to
//! the old address no longer covers anything. So this type allocates once, for
//! good, and refuses to hold more than it was built for. A secret whose size is
//! not known in advance does not belong here.
//!
//! # Failure is reported, never hidden
//!
//! Locking needs a privilege — `RLIMIT_MEMLOCK` on Linux, a working set quota
//! on Windows — that an ordinary account does not always have. The buffer is
//! still created and still wiped; only the swap guarantee is missing, and
//! [`LockedSecret::lock_state`] says so, so the posture panel can. Failing hard
//! would make Orion unusable on a default Linux account, and silently ignoring
//! it would keep a promise the screen makes without backing.

use zeroize::Zeroize as _;

/// Whether the buffer's pages are held in RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// Pages locked: they will not reach swap or hibernation.
    Locked,
    /// The platform refused. The buffer is still wiped on drop.
    Refused,
    /// No locking primitive on this platform.
    Unsupported,
}

impl LockState {
    /// Whether the swap guarantee actually holds.
    ///
    /// `Refused` and `Unsupported` are the same answer for a caller deciding
    /// what to promise — they differ only in what the log should say.
    pub fn holds(self) -> bool {
        matches!(self, Self::Locked)
    }

    /// Sentence for the posture panel.
    pub fn detail(self) -> &'static str {
        match self {
            Self::Locked => {
                "Pages verrouillées en RAM : les secrets n'atteignent ni le fichier \
                 d'échange ni celui d'hibernation."
            }
            Self::Refused => {
                "Verrouillage mémoire refusé par le système : un secret peut être \
                 écrit dans le fichier d'échange. Le chiffrement de volume reste obligatoire."
            }
            Self::Unsupported => {
                "Aucun verrouillage mémoire sur cette plateforme : le \
                 chiffrement de volume reste obligatoire."
            }
        }
    }
}

/// A fixed-capacity secret buffer, locked in RAM where the platform allows it.
pub struct LockedSecret {
    /// Boxed so the address is stable: locking a stack buffer would cover an
    /// address the value stops living at as soon as it is moved.
    buffer: Box<[u8]>,
    length: usize,
    lock_state: LockState,
}

impl LockedSecret {
    /// Allocates a buffer of exactly `capacity` bytes and tries to lock it.
    pub fn with_capacity(capacity: usize) -> Self {
        let mut buffer = vec![0u8; capacity].into_boxed_slice();
        let lock_state = platform::lock(&mut buffer);
        Self {
            buffer,
            length: 0,
            lock_state,
        }
    }

    /// Copies `value` in, refusing anything the buffer cannot hold.
    ///
    /// Refusing rather than growing is the point: a reallocation would leave
    /// the previous content in a freed, unwiped, unlocked block.
    pub fn set(&mut self, value: &[u8]) -> Result<(), CapacityExceeded> {
        if value.len() > self.buffer.len() {
            return Err(CapacityExceeded {
                capacity: self.buffer.len(),
                wanted: value.len(),
            });
        }
        // Wipe the whole buffer first: a shorter value would otherwise leave
        // the tail of the previous one readable.
        self.buffer.zeroize();
        self.buffer[..value.len()].copy_from_slice(value);
        self.length = value.len();
        Ok(())
    }

    /// Exposes the content. Named like [`crate::SecretString::expose`], and for
    /// the same reason.
    pub fn expose(&self) -> &[u8] {
        &self.buffer[..self.length]
    }

    pub fn len(&self) -> usize {
        self.length
    }

    pub fn is_empty(&self) -> bool {
        self.length == 0
    }

    pub fn capacity(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the pages are genuinely locked.
    pub fn lock_state(&self) -> LockState {
        self.lock_state
    }
}

impl Drop for LockedSecret {
    fn drop(&mut self) {
        // Wipe before unlocking: unlocking first would let the pages become
        // swappable while they still hold the secret.
        self.buffer.zeroize();
        platform::unlock(&mut self.buffer);
    }
}

/// `Debug` never prints the content, nor its length.
impl std::fmt::Debug for LockedSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("LockedSecret")
            .field("content", &"***")
            .field("lock_state", &self.lock_state)
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("secret de {wanted} octets pour une capacité de {capacity}")]
pub struct CapacityExceeded {
    pub capacity: usize,
    pub wanted: usize,
}

#[cfg(target_os = "linux")]
mod platform {
    use super::LockState;

    pub fn lock(buffer: &mut [u8]) -> LockState {
        if buffer.is_empty() {
            return LockState::Locked;
        }
        // SAFETY: the pointer and length describe a live allocation this
        // process owns, which is exactly what `mlock` expects.
        let locked = unsafe { libc::mlock(buffer.as_ptr().cast(), buffer.len()) };
        if locked == 0 {
            LockState::Locked
        } else {
            // Typically `RLIMIT_MEMLOCK` on an ordinary account. Reported, not
            // fatal: the buffer is still wiped on drop.
            LockState::Refused
        }
    }

    pub fn unlock(buffer: &mut [u8]) {
        if buffer.is_empty() {
            return;
        }
        // SAFETY: same allocation as the matching `lock`.
        unsafe { libc::munlock(buffer.as_ptr().cast(), buffer.len()) };
    }
}

#[cfg(windows)]
mod platform {
    use super::LockState;
    use windows_sys::Win32::System::Memory::{VirtualLock, VirtualUnlock};

    pub fn lock(buffer: &mut [u8]) -> LockState {
        if buffer.is_empty() {
            return LockState::Locked;
        }
        // SAFETY: the pointer and length describe a live allocation this
        // process owns.
        let locked = unsafe { VirtualLock(buffer.as_mut_ptr().cast(), buffer.len()) };
        if locked != 0 {
            LockState::Locked
        } else {
            // Usually the process working-set quota. Reported, not fatal.
            LockState::Refused
        }
    }

    pub fn unlock(buffer: &mut [u8]) {
        if buffer.is_empty() {
            return;
        }
        // SAFETY: same allocation as the matching `lock`.
        unsafe { VirtualUnlock(buffer.as_mut_ptr().cast(), buffer.len()) };
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod platform {
    use super::LockState;

    pub fn lock(_buffer: &mut [u8]) -> LockState {
        LockState::Unsupported
    }

    pub fn unlock(_buffer: &mut [u8]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_round_trips() {
        let mut secret = LockedSecret::with_capacity(32);
        secret.set(b"cle-privee-de-32-octets-exactly!").unwrap();
        assert_eq!(secret.expose(), b"cle-privee-de-32-octets-exactly!");
        assert_eq!(secret.len(), 32);
        assert_eq!(secret.capacity(), 32);
    }

    /// Growing would reallocate, leaving the previous content in a freed,
    /// unwiped, unlocked block. Refusing is the whole point.
    #[test]
    fn an_oversized_secret_is_refused_rather_than_growing() {
        let mut secret = LockedSecret::with_capacity(8);
        let error = secret.set(b"beaucoup trop long").unwrap_err();
        assert_eq!(
            error,
            CapacityExceeded {
                capacity: 8,
                wanted: 18
            }
        );
        assert!(
            secret.is_empty(),
            "a refused write must leave nothing behind"
        );
    }

    /// A shorter value must not leave the tail of the previous one readable.
    #[test]
    fn a_shorter_value_wipes_the_previous_tail() {
        let mut secret = LockedSecret::with_capacity(16);
        secret.set(b"AAAAAAAAAAAAAAAA").unwrap();
        secret.set(b"BB").unwrap();
        assert_eq!(secret.expose(), b"BB");
        // Reach past the logical length: the rest of the owned buffer must be
        // zero, not the previous secret.
        let whole = &secret.buffer[..];
        assert!(
            whole[2..].iter().all(|byte| *byte == 0),
            "the previous value is still readable past the new one"
        );
    }

    #[test]
    fn debug_reveals_neither_the_content_nor_its_length() {
        let mut secret = LockedSecret::with_capacity(32);
        secret.set(b"psk-ultra-confidentiel").unwrap();
        let rendered = format!("{secret:?}");
        assert!(!rendered.contains("psk-ultra"), "leak: {rendered}");
        assert!(!rendered.contains("22"), "length leaked: {rendered}");
    }

    /// The guarantee must be reported, not assumed: a caller that promises
    /// "no swap" has to be able to check it.
    #[test]
    fn the_lock_state_is_reported() {
        let secret = LockedSecret::with_capacity(32);
        let state = secret.lock_state();
        assert!(!state.detail().is_empty());
        // On Linux a default account usually has enough `RLIMIT_MEMLOCK` for
        // one page, but not always — CI containers vary. What must hold is
        // that the answer is never a silent "yes".
        assert!(
            matches!(
                state,
                LockState::Locked | LockState::Refused | LockState::Unsupported
            ),
            "unexpected state: {state:?}"
        );
        assert_eq!(state.holds(), state == LockState::Locked);
    }

    #[test]
    fn only_a_real_lock_holds() {
        assert!(LockState::Locked.holds());
        assert!(!LockState::Refused.holds());
        assert!(
            !LockState::Unsupported.holds(),
            "an absent primitive must never be reported as a guarantee"
        );
    }

    #[test]
    fn an_empty_buffer_is_harmless() {
        let secret = LockedSecret::with_capacity(0);
        assert!(secret.is_empty());
        assert_eq!(secret.expose(), b"");
    }
}
