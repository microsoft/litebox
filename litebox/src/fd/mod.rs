//! File descriptors used in LiteBox

mod temp_old_stuff;
pub(crate) use temp_old_stuff::InternalFd;
pub use temp_old_stuff::{FileFd, SocketFd};

/// An explicitly-private shared-common element of `FileFd` and `SocketFd`, allowing convenient
/// re-implementation.
///
/// Denotes an owned (non-clonable) token of ownership over a file descriptor.
pub(crate) struct OwnedFd {
    raw: u32,
    closed: bool,
}

impl OwnedFd {
    /// Produce a new owned token from a raw index
    ///
    /// Panics if outside the u32 range
    pub(crate) fn new(raw: usize) -> Self {
        Self {
            raw: raw.try_into().unwrap(),
            closed: false,
        }
    }

    /// Check if it is closed
    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    /// Mark it as closed
    pub(crate) fn mark_as_closed(&mut self) {
        assert!(!self.is_closed());
        self.closed = true;
    }

    /// Obtain the raw index it was created with
    pub(crate) fn as_usize(&self) -> usize {
        assert!(!self.is_closed());
        self.raw.try_into().unwrap()
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.closed {
            // This has been closed out by a valid close operation
        } else {
            // The owned fd is dropped without being consumed by a `close` operation that has
            // properly marked it as being safely closed
            #[cfg(feature = "panic_on_unclosed_fd_drop")]
            panic!("Un-closed OwnedFd ({}) being dropped", self.raw)
        }
    }
}
