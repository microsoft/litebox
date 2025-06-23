//! Transitional module, that is intended to be removed before making the PR.

use super::InternalFd;
use super::OwnedFd;

/// An owned file descriptor for files.
///
/// This file descriptor **must** be consumed by a `close` operation. Otherwise, (when using crate
/// feature `panic_on_unclosed_fd_drop`), will panic if dropped without closing.
pub struct FileFd {
    pub(crate) x: OwnedFd,
}

impl FileFd {
    /// Get the equivalent internal-fd
    pub(crate) fn as_internal_fd(&self) -> InternalFd {
        assert!(!self.x.is_closed());
        InternalFd {
            raw: self.x.raw,
            __kind: 0,
        }
    }
}

/// An owned file descriptor for sockets.
///
/// This file descriptor **must** be consumed by a `close` operation. Otherwise, (when using crate
/// feature `panic_on_unclosed_fd_drop`), will panic if dropped without closing.
pub struct SocketFd {
    pub(crate) x: OwnedFd,
}

impl SocketFd {
    /// Get the equivalent internal-fd
    pub(crate) fn as_internal_fd(&self) -> InternalFd {
        assert!(!self.x.is_closed());
        InternalFd {
            raw: self.x.raw,
            __kind: 1,
        }
    }
}
