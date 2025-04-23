//! Transitional module, that is intended to be removed before making the PR.

/// A crate-internal representation of file descriptors that supports cloning/copying, and does
/// *not* indicate validity/existence/ownership.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum InternalFd {
    File(u32),
    Socket(u32),
}

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
        InternalFd::File(self.x.raw)
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
        InternalFd::Socket(self.x.raw)
    }
}
