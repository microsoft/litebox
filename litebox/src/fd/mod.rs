//! File descriptors used in LiteBox

mod temp_old_stuff;
pub(crate) use temp_old_stuff::InternalFd;
pub use temp_old_stuff::{FileFd, SocketFd};

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use thiserror::Error;

use crate::{
    LiteBox,
    sync::{self, RwLock},
};

/// Storage of file descriptors and their entries.
///
/// This particular object is also able to turn safely-typed file descriptors to/from unsafely-typed
/// integers, with a reasonable amount of safety---this will not be able to check for "ABA" style
/// issues, but will at least prevent using a descriptor for an unintended subsystem at the point of
/// conversion.
pub struct Descriptors<Platform: sync::RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    entries: RwLock<Platform, Vec<Option<Arc<DescriptorEntry<Platform>>>>>,
    /// Stored FDs are used to provide raw integer values in a safer way.
    stored_fds: Vec<Option<OwnedFd>>,
}

impl<Platform: sync::RawSyncPrimitivesProvider> Descriptors<Platform> {
    /// Explicitly crate-internal: Create a new empty descriptor table.
    ///
    /// This should only be invoked once per LiteBox system.
    pub(crate) fn new(litebox: &LiteBox<Platform>) -> Self {
        let litebox = litebox.clone();
        let entries = litebox.sync().new_rwlock(vec![]);
        Self {
            litebox,
            entries,
            stored_fds: vec![],
        }
    }

    /// Insert `entry` into the descriptor table, returning an `OwnedFd` to this entry.
    pub(crate) fn insert(&mut self, entry: DescriptorEntry<Platform>) -> OwnedFd {
        let mut entries = self.entries.write();
        let idx = entries.iter().position(Option::is_none).unwrap_or_else(|| {
            entries.push(None);
            entries.len() - 1
        });
        let old = entries[idx].replace(Arc::new(entry));
        assert!(old.is_none());
        OwnedFd::new(idx)
    }

    /// Removes the entry at `fd`, closing out the file descriptor.
    ///
    /// Returns the descriptor entry if it is unique (i.e., it was not duplicated, or all duplicates
    /// have been cleared out).
    pub(crate) fn remove(&mut self, mut fd: OwnedFd) -> Option<DescriptorEntry<Platform>> {
        let Some(old) = self.entries.write()[fd.as_usize()].take() else {
            unreachable!();
        };
        fd.mark_as_closed();
        Arc::into_inner(old)
    }

    /// Get the entry at `fd`.
    pub(crate) fn get(&self, fd: &OwnedFd) -> Arc<DescriptorEntry<Platform>> {
        // Since the `fd` is borrowed, it must still exist, thus this index will always exist, as
        // well as have a value within it.
        Arc::clone(self.entries.read()[fd.as_usize()].as_ref().unwrap())
    }

    /// Get the corresponding integer value of the provided `fd`.
    ///
    /// This explicitly consumes the `fd`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics are only wthin assertions"
    )]
    pub fn fd_into_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: TypedFd<Subsystem>,
    ) -> usize {
        let raw = fd.x.as_usize();
        debug_assert!(Subsystem::matches_entry(
            self.entries.read()[raw].as_ref().unwrap().kind()
        ));
        if self.stored_fds.len() <= raw {
            self.stored_fds.resize_with(raw + 1, || None);
        }
        let old = self.stored_fds[raw].replace(fd.x);
        assert!(old.is_none());
        raw
    }

    /// Borrow the typed FD for the raw integer value of the `fd`.
    ///
    /// This operation is only reasonable to do if there is only a "short duration" between
    /// generation of the typed FD and its use; otherwise, there can be no guarantee that the
    /// particular FD hasn't changed out entirely.
    ///
    /// Returns `Ok` iff the `fd` exists and is for the correct subsystem.
    ///
    /// To fully remove this FD from the system to make it available to consume, see
    /// [`Self::fd_consume_raw_integer`].
    pub fn fd_from_raw_integer<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: usize,
    ) -> Result<&TypedFd<Subsystem>, ErrRawIntFd> {
        let entries = self.entries.read();
        let Some(Some(entry)) = entries.get(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        if !Subsystem::matches_entry(entry.kind()) {
            return Err(ErrRawIntFd::InvalidSubsystem);
        }
        let Some(Some(stored_fd)) = self.stored_fds.get(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        let owned_fd: &OwnedFd = stored_fd;
        // SAFETY: Since `TypedFd` is `#[repr(transparent)]`, we can safety transmute the type over
        // (it is essentially the correct type, we simply want to expose a wrapped-type variant of
        // it). We've just confirmed that it is the correct subsystem too.
        let typed_fd: &TypedFd<Subsystem> = unsafe { &*core::ptr::from_ref(owned_fd).cast() };
        Ok(typed_fd)
    }

    /// Obtain the typed FD for the raw integer value of the `fd`.
    ///
    /// This operation will "consume" the raw integer (thus future [`Self::fd_from_raw_integer`]
    /// might not refer to this file descriptor unless it is returned back via
    /// [`Self::fd_into_raw_integer`]).
    ///
    /// You almost definitely want [`Self::fd_from_raw_integer`] instead, and should only use this
    /// if you really know you want to consume the descriptor.
    pub fn fd_consume_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: usize,
    ) -> Result<TypedFd<Subsystem>, ErrRawIntFd> {
        let entries = self.entries.read();
        let Some(Some(entry)) = entries.get(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        if !Subsystem::matches_entry(entry.kind()) {
            return Err(ErrRawIntFd::InvalidSubsystem);
        }
        let Some(stored_fd) = self.stored_fds.get_mut(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        let Some(owned_fd) = stored_fd.take() else {
            return Err(ErrRawIntFd::NotFound);
        };
        Ok(TypedFd {
            _phantom: PhantomData,
            x: owned_fd,
        })
    }
}

/// LiteBox subsystems that support having file descriptors.
pub trait FdEnabledSubsystem {
    #[doc(hidden)]
    #[must_use]
    fn matches_entry(entry: EntryKind) -> bool;
}

/// Possible errors from [`Descriptors::fd_from_raw_integer`] and
/// [`Descriptors::fd_consume_raw_integer`].
#[derive(Error, Debug)]
pub enum ErrRawIntFd {
    #[error("no such file descriptor found")]
    NotFound,
    #[error("fd for invalid subsystem")]
    InvalidSubsystem,
}

/// A crate-internal entry for a descriptor.
///
/// Any new introduction of a file-system or network or similar would need its own entry to be
/// provided here in order to be able to store descriptors.
pub(crate) enum DescriptorEntry<Platform: sync::RawSyncPrimitivesProvider> {
    Socket(crate::net::SocketHandle),
    InMemFS(crate::fs::in_mem::Descriptor<Platform>),
}

impl<Platform: sync::RawSyncPrimitivesProvider> DescriptorEntry<Platform> {
    fn kind(&self) -> EntryKind {
        match self {
            DescriptorEntry::Socket(_) => EntryKind::Socket,
            DescriptorEntry::InMemFS(_) => EntryKind::InMemFS,
        }
    }
}

/// A crate-internal entry-kind for a descriptor.
///
/// We are forced to keep this `pub` because of [`FdEnabledSubsystem`]. We'd ideally keep this
/// `pub(crate)`, but must instead live with just the `#[doc(hidden)]` instead.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EntryKind {
    Socket,
    InMemFS,
}

/// A file descriptor that refers to entries by the `Subsystem`.
#[repr(transparent)] // this allows us to transmute safely
pub struct TypedFd<Subsystem: FdEnabledSubsystem> {
    _phantom: PhantomData<Subsystem>,
    x: OwnedFd,
}

/// An explicitly-private shared-common element of [`TypedFd`], denoting an owned (non-clonable)
/// token of ownership over a file descriptor.
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
