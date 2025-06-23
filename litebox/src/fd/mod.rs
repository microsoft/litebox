//! File descriptors used in LiteBox

#![expect(
    dead_code,
    reason = "still under development, remove before merging PR"
)]

mod temp_old_stuff;
pub(crate) use temp_old_stuff::InternalFd;
pub use temp_old_stuff::{FileFd, SocketFd};

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use thiserror::Error;

use crate::LiteBox;
use crate::sync::{RawSyncPrimitivesProvider, RwLock};

/// Storage of file descriptors and their entries.
///
/// This particular object is also able to turn safely-typed file descriptors to/from unsafely-typed
/// integers, with a reasonable amount of safety---this will not be able to check for "ABA" style
/// issues, but will at least prevent using a descriptor for an unintended subsystem at the point of
/// conversion.
pub struct Descriptors<Platform: RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    entries: Vec<Option<Arc<RwLock<Platform, DescriptorEntry>>>>,
    /// Stored FDs are used to provide raw integer values in a safer way.
    stored_fds: Vec<Option<OwnedFd>>,
}

impl<Platform: RawSyncPrimitivesProvider> Descriptors<Platform> {
    /// Explicitly crate-internal: Create a new empty descriptor table.
    ///
    /// This should only be invoked once per LiteBox system.
    pub(crate) fn new(litebox: &LiteBox<Platform>) -> Self {
        let litebox = litebox.clone();
        Self {
            litebox,
            entries: vec![],
            stored_fds: vec![],
        }
    }

    /// Insert `entry` into the descriptor table, returning an `OwnedFd` to this entry.
    pub(crate) fn insert(&mut self, entry: DescriptorEntry) -> OwnedFd {
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        let old = self.entries[idx].replace(Arc::new(self.litebox.sync().new_rwlock(entry)));
        assert!(old.is_none());
        OwnedFd::new(idx)
    }

    /// Removes the entry at `fd`, closing out the file descriptor.
    ///
    /// Returns the descriptor entry if it is unique (i.e., it was not duplicated, or all duplicates
    /// have been cleared out).
    pub(crate) fn remove(&mut self, mut fd: OwnedFd) -> Option<DescriptorEntry> {
        let Some(old) = self.entries[fd.as_usize()].take() else {
            unreachable!();
        };
        fd.mark_as_closed();
        Arc::into_inner(old).map(RwLock::into_inner)
    }

    /// Use the entry at `fd` as read-only.
    pub(crate) fn with_entry<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> R
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad transmute
        // somewhere.
        let entry = self.entries[fd.x.as_usize()].as_ref().unwrap().read();
        f(entry.as_subsystem::<Subsystem>())
    }

    /// Use the entry at `fd` as mutably.
    pub(crate) fn with_entry_mut<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> R
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&mut Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad transmute
        // somewhere.
        let mut entry = self.entries[fd.x.as_usize()].as_ref().unwrap().write();
        f(entry.as_subsystem_mut::<Subsystem>())
    }

    /// Get the corresponding integer value of the provided `fd`.
    ///
    /// This explicitly consumes the `fd`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics are only within assertions"
    )]
    pub fn fd_into_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: TypedFd<Subsystem>,
    ) -> usize {
        let raw = fd.x.as_usize();
        debug_assert_eq!(
            self.entries[raw].as_ref().unwrap().read().kind(),
            Subsystem::KIND
        );
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
        let Some(Some(entry)) = self.entries.get(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        if entry.read().kind() != Subsystem::KIND {
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
        let Some(Some(entry)) = self.entries.get(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        if entry.read().kind() != Subsystem::KIND {
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
    type Entry: FdEnabledSubsystemEntry + 'static;
    #[doc(hidden)]
    const KIND: EntryKind;
}

/// Entries for a specific [`FdEnabledSubsystem`]
#[doc(hidden)]
pub trait FdEnabledSubsystemEntry {
    /// This returns the [`EntryKind`] of the entry. This is expected to be a constant function (we
    /// would ideally define this as an associated constant; it is maintained as a function taking
    /// `&self` only for dyn-compatibility reasons).
    fn kind(&self) -> EntryKind;
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
pub(crate) struct DescriptorEntry {
    entry: alloc::boxed::Box<dyn FdEnabledSubsystemEntry>,
}

impl DescriptorEntry {
    fn kind(&self) -> EntryKind {
        self.entry.kind()
    }

    /// Obtains `self` as the subsystem's entry type.
    ///
    /// Panics if invalid for the particular subsystem.
    fn as_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> &Subsystem::Entry {
        if core::any::TypeId::of::<&Subsystem::Entry>()
            != core::any::Any::type_id(self.entry.as_ref())
        {
            unreachable!(
                "\
                The types in `FdEnabledSubsystem` must be perfectly \
                in sync with `DescriptorEntry`."
            )
        }
        // SAFETY: We just confirmed they are the same type.
        unsafe { &*core::ptr::from_ref(self.entry.as_ref()).cast() }
    }

    /// Obtains `self` as the subsystem's entry type, mutably.
    ///
    /// Panics if invalid for the particular subsystem.
    fn as_subsystem_mut<Subsystem: FdEnabledSubsystem>(&mut self) -> &mut Subsystem::Entry {
        if core::any::TypeId::of::<&mut Subsystem::Entry>()
            != core::any::Any::type_id(self.entry.as_mut())
        {
            unreachable!(
                "\
                The types in `FdEnabledSubsystem` must be perfectly \
                in sync with `DescriptorEntry`."
            )
        }
        // SAFETY: We just confirmed they are the same type.
        unsafe { &mut *core::ptr::from_mut(self.entry.as_mut()).cast() }
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
