//! File descriptors used in LiteBox

#![expect(
    dead_code,
    reason = "still under development, remove before merging PR"
)]

use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use thiserror::Error;

use crate::LiteBox;
use crate::sync::{RawSyncPrimitivesProvider, RwLock};
use crate::utilities::anymap::AnyMap;

#[cfg(test)]
mod tests;

/// Storage of file descriptors and their entries.
///
/// This particular object is also able to turn safely-typed file descriptors to/from unsafely-typed
/// integers, with a reasonable amount of safety---this will not be able to check for "ABA" style
/// issues, but will at least prevent using a descriptor for an unintended subsystem at the point of
/// conversion.
pub struct Descriptors<Platform: RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    entries: Vec<Option<IndividualEntry<Platform>>>,
    /// Stored FDs are used to provide raw integer values in a safer way.
    stored_fds: Vec<Option<OwnedFd>>,
}

impl<Platform: RawSyncPrimitivesProvider> Descriptors<Platform> {
    /// Explicitly crate-internal: Create a new empty descriptor table.
    ///
    /// This is expected to be invoked only by [`crate::LiteBox`]'s creation method, and should not
    /// be invoked anywhere else in the codebase.
    pub(crate) fn new_from_litebox_creation(litebox: &LiteBox<Platform>) -> Self {
        let litebox = litebox.clone();
        Self {
            litebox,
            entries: vec![],
            stored_fds: vec![],
        }
    }

    /// Insert `entry` into the descriptor table, returning an `OwnedFd` to this entry.
    pub(crate) fn insert<Subsystem: FdEnabledSubsystem>(
        &mut self,
        entry: impl Into<Subsystem::Entry>,
    ) -> TypedFd<Subsystem> {
        let entry = DescriptorEntry {
            entry: alloc::boxed::Box::new(entry.into()),
            metadata: AnyMap::new(),
        };
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        let old =
            self.entries[idx].replace(IndividualEntry::new(self.litebox.sync().new_rwlock(entry)));
        assert!(old.is_none());
        TypedFd {
            _phantom: PhantomData,
            x: OwnedFd::new(idx),
        }
    }

    /// Removes the entry at `fd`, closing out the file descriptor.
    ///
    /// Returns the descriptor entry if it is unique (i.e., it was not duplicated, or all duplicates
    /// have been cleared out).
    pub(crate) fn remove<Subsystem: FdEnabledSubsystem>(
        &mut self,
        mut fd: TypedFd<Subsystem>,
    ) -> Option<Subsystem::Entry> {
        let Some(old) = self.entries[fd.x.as_usize()].take() else {
            unreachable!();
        };
        fd.x.mark_as_closed();
        Arc::into_inner(old.x)
            .map(RwLock::into_inner)
            .map(DescriptorEntry::into_subsystem_entry::<Subsystem>)
    }

    /// An iterator of descriptors and entries for a subsystem
    ///
    /// Note: each of the entries take locks, thus should not be held on to for too long, in order
    /// to prevent dead-locks.
    pub(crate) fn iter<Subsystem: FdEnabledSubsystem>(
        &self,
    ) -> impl Iterator<Item = (InternalFd, impl core::ops::Deref<Target = Subsystem::Entry>)> {
        self.entries.iter().enumerate().filter_map(|(i, entry)| {
            entry.as_ref().and_then(|e| {
                let entry = e.read();
                if entry.matches_subsystem::<Subsystem>() {
                    Some((
                        InternalFd {
                            raw: i.try_into().unwrap(),
                        },
                        crate::sync::RwLockReadGuard::map(entry, |e| e.as_subsystem::<Subsystem>()),
                    ))
                } else {
                    None
                }
            })
        })
    }

    /// An iterator of descriptors and (mutable) entries for a subsystem
    ///
    /// Note: each of the entries take locks, thus should not be held on to for too long, in order
    /// to prevent dead-locks.
    pub(crate) fn iter_mut<Subsystem: FdEnabledSubsystem>(
        &mut self,
    ) -> impl Iterator<
        Item = (
            InternalFd,
            impl core::ops::DerefMut<Target = Subsystem::Entry>,
        ),
    > {
        self.entries
            .iter_mut()
            .enumerate()
            .filter_map(|(i, entry)| {
                entry.as_mut().and_then(|e| {
                    let entry = e.write();
                    if entry.matches_subsystem::<Subsystem>() {
                        Some((
                            InternalFd {
                                raw: i.try_into().unwrap(),
                            },
                            crate::sync::RwLockWriteGuard::map(entry, |e| {
                                e.as_subsystem_mut::<Subsystem>()
                            }),
                        ))
                    } else {
                        None
                    }
                })
            })
    }

    /// Use the entry at `fd` as read-only.
    pub(crate) fn with_entry<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> R
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
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
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let mut entry = self.entries[fd.x.as_usize()].as_ref().unwrap().write();
        f(entry.as_subsystem_mut::<Subsystem>())
    }

    /// Use the entry at `internal_fd` as mutably.
    ///
    /// NOTE: Ideally, prefer using [`Self::with_entry_mut`] instead of this, since it provides a
    /// nicer experience with respect to types. This current function is only to be used with
    /// specialized usages that involve dealing with stuff around [`Self::iter`] and locking
    /// disciplines, and thus should be considered an "advanced" usage.
    ///
    /// `f` is run iff it is the correct subsystem. Returns `Some` iff it is the correct subsystem.
    pub(crate) fn with_entry_mut_via_internal_fd<Subsystem, F, R>(
        &self,
        internal_fd: InternalFd,
        f: F,
    ) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&mut Subsystem::Entry) -> R,
    {
        let mut entry = self.entries[usize::try_from(internal_fd.raw).unwrap()]
            .as_ref()
            .unwrap()
            .write();
        if entry.matches_subsystem::<Subsystem>() {
            Some(f(entry.as_subsystem_mut::<Subsystem>()))
        } else {
            None
        }
    }

    /// Get the entry at `fd`.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry`] when possible, to make life easier.
    pub(crate) fn get_entry<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> impl core::ops::Deref<Target = Subsystem::Entry> + use<'_, Platform, Subsystem> {
        crate::sync::RwLockReadGuard::map(
            self.entries[fd.x.as_usize()].as_ref().unwrap().read(),
            |e| e.as_subsystem::<Subsystem>(),
        )
    }

    /// Get the entry at `fd`, mutably.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry_mut`] when possible, to make life easier.
    pub(crate) fn get_entry_mut<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> impl core::ops::DerefMut<Target = Subsystem::Entry> + use<'_, Platform, Subsystem> {
        crate::sync::RwLockWriteGuard::map(
            self.entries[fd.x.as_usize()].as_ref().unwrap().write(),
            |e| e.as_subsystem_mut::<Subsystem>(),
        )
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
        let ret = self.stored_fds.iter().position(Option::is_none);
        let ret = ret.unwrap_or_else(|| {
            self.stored_fds.push(None);
            self.stored_fds.len() - 1
        });
        debug_assert!(
            self.entries[fd.x.as_usize()]
                .as_ref()
                .unwrap()
                .read()
                .matches_subsystem::<Subsystem>()
        );
        let old = self.stored_fds[ret].replace(fd.x);
        assert!(old.is_none());
        ret
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
        let Some(Some(stored_fd)) = self.stored_fds.get(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        let owned_fd: &OwnedFd = stored_fd;
        let Some(Some(entry)) = self.entries.get(stored_fd.as_usize()) else {
            return Err(ErrRawIntFd::NotFound);
        };
        if !entry.read().matches_subsystem::<Subsystem>() {
            return Err(ErrRawIntFd::InvalidSubsystem);
        }
        // SAFETY: Since `TypedFd` is `#[repr(transparent)]`, we can safety cast the type over (it
        // is essentially the correct type, we simply want to expose a wrapped-type variant of it).
        // We've just confirmed that it is the correct subsystem too.
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
        let Some(stored_fd) = self.stored_fds.get_mut(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        match stored_fd {
            None => return Err(ErrRawIntFd::NotFound),
            Some(x) => {
                let Some(Some(entry)) = self.entries.get(x.as_usize()) else {
                    return Err(ErrRawIntFd::NotFound);
                };
                if !entry.read().matches_subsystem::<Subsystem>() {
                    return Err(ErrRawIntFd::InvalidSubsystem);
                }
            }
        }
        let Some(owned_fd) = stored_fd.take() else {
            return Err(ErrRawIntFd::NotFound);
        };
        Ok(TypedFd {
            _phantom: PhantomData,
            x: owned_fd,
        })
    }

    /// Apply `f` on metadata at an fd, if it exists.
    ///
    /// This returns the most-specific metadata available for the file descriptor---specifically, if
    /// both [`Self::set_fd_metadata`] and [`Self::set_entry_metadata`]) are run on the same
    /// fd, this will only return the value from the fd one, which will shadow the file one. If no
    /// fd-specific one is set, this returns the entry-specific one.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn with_metadata<Subsystem, T, R>(
        &self,
        fd: &TypedFd<Subsystem>,
        f: impl FnOnce(&T) -> R,
    ) -> Result<R, MetadataError>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Send + Sync,
    {
        let ind_entry = self.entries[fd.x.as_usize()].as_ref().unwrap();
        match ind_entry.metadata.get::<T>() {
            Some(m) => Ok(f(m)),
            None => ind_entry
                .read()
                .metadata
                .get::<T>()
                .map(f)
                .ok_or(MetadataError::NoSuchMetadata),
        }
    }

    /// Similar to [`Self::with_metadata`] but mutable.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn with_metadata_mut<Subsystem, T, R>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        f: impl FnOnce(&mut T) -> R,
    ) -> Result<R, MetadataError>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Send + Sync,
    {
        let ind_entry = self.entries[fd.x.as_usize()].as_mut().unwrap();
        match ind_entry.metadata.get_mut::<T>() {
            Some(m) => Ok(f(m)),
            None => ind_entry
                .write()
                .metadata
                .get_mut::<T>()
                .map(f)
                .ok_or(MetadataError::NoSuchMetadata),
        }
    }

    /// Store arbitrary metadata into a file.
    ///
    /// Such metadata is visible to any open fd on the entry associated with the fd. See similar
    /// [`Self::set_fd_metadata`] which is specific to fds, and does not alias the metadata.
    ///
    /// Returns the old metadata if any such metadata exists.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn set_entry_metadata<Subsystem, T>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        metadata: T,
    ) -> Option<T>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Send + Sync,
    {
        self.entries[fd.x.as_usize()]
            .as_ref()
            .unwrap()
            .x
            .write()
            .metadata
            .insert(metadata)
    }

    /// Store arbitrary metdata into a file descriptor.
    ///
    /// Such metadata is specific to the current fd and is NOT shared with other open fds to the
    /// same entry. See the similar [`Self::set_entry_metadata`] which aliases metadata over all fds
    /// opened for the same entry.
    #[expect(
        clippy::missing_panics_doc,
        reason = "the invariants guarantee that the unwrap panics cannot occur"
    )]
    pub fn set_fd_metadata<Subsystem, T>(
        &mut self,
        fd: &TypedFd<Subsystem>,
        metadata: T,
    ) -> Option<T>
    where
        Subsystem: FdEnabledSubsystem,
        T: core::any::Any + Send + Sync,
    {
        self.entries[fd.x.as_usize()]
            .as_mut()
            .unwrap()
            .metadata
            .insert(metadata)
    }
}

/// LiteBox subsystems that support having file descriptors.
pub trait FdEnabledSubsystem: Sized {
    #[doc(hidden)]
    type Entry: FdEnabledSubsystemEntry + 'static;
}

/// Entries for a specific [`FdEnabledSubsystem`]
#[doc(hidden)]
pub trait FdEnabledSubsystemEntry: core::any::Any {}

/// Possible errors from [`Descriptors::fd_from_raw_integer`] and
/// [`Descriptors::fd_consume_raw_integer`].
#[derive(Error, Debug)]
pub enum ErrRawIntFd {
    #[error("no such file descriptor found")]
    NotFound,
    #[error("fd for invalid subsystem")]
    InvalidSubsystem,
}

/// Possible errors from getting metadata
#[derive(Error, Debug)]
pub enum MetadataError {
    #[error("no such metadata available")]
    NoSuchMetadata,
}

/// A module-internal fd-specific individual entry
struct IndividualEntry<Platform: RawSyncPrimitivesProvider> {
    x: Arc<RwLock<Platform, DescriptorEntry>>,
    metadata: AnyMap,
}
impl<Platform: RawSyncPrimitivesProvider> core::ops::Deref for IndividualEntry<Platform> {
    type Target = Arc<RwLock<Platform, DescriptorEntry>>;
    fn deref(&self) -> &Self::Target {
        &self.x
    }
}
impl<Platform: RawSyncPrimitivesProvider> IndividualEntry<Platform> {
    fn new(x: RwLock<Platform, DescriptorEntry>) -> Self {
        Self {
            x: Arc::new(x),
            metadata: AnyMap::new(),
        }
    }
}

/// A crate-internal entry for a descriptor.
pub(crate) struct DescriptorEntry {
    entry: alloc::boxed::Box<dyn FdEnabledSubsystemEntry>,
    metadata: AnyMap,
}

impl DescriptorEntry {
    /// Check if this entry matches the specified subsystem
    #[must_use]
    fn matches_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> bool {
        core::any::TypeId::of::<Subsystem::Entry>() == core::any::Any::type_id(self.entry.as_ref())
    }

    /// Obtains `self` as the subsystem's entry type.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn as_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> &Subsystem::Entry {
        (self.entry.as_ref() as &dyn core::any::Any)
            .downcast_ref()
            .unwrap()
    }

    /// Obtains `self` as the subsystem's entry type, mutably.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn as_subsystem_mut<Subsystem: FdEnabledSubsystem>(&mut self) -> &mut Subsystem::Entry {
        (self.entry.as_mut() as &mut dyn core::any::Any)
            .downcast_mut()
            .unwrap()
    }

    /// Obtains `self` as the subsystem's entry type.
    ///
    /// # Panics
    ///
    /// Panics if invalid for the particular subsystem.
    fn into_subsystem_entry<Subsystem: FdEnabledSubsystem>(self) -> Subsystem::Entry {
        *(self.entry as alloc::boxed::Box<dyn core::any::Any>)
            .downcast()
            .unwrap()
    }
}

/// A file descriptor that refers to entries by the `Subsystem`.
#[repr(transparent)] // this allows us to cast safely
pub struct TypedFd<Subsystem: FdEnabledSubsystem> {
    _phantom: PhantomData<Subsystem>,
    x: OwnedFd,
}

impl<Subsystem: FdEnabledSubsystem> TypedFd<Subsystem> {
    /// Get the "internal FD"
    pub(crate) fn as_internal_fd(&self) -> InternalFd {
        assert!(!self.x.is_closed());
        InternalFd { raw: self.x.raw }
    }
}

/// A crate-internal representation of file descriptors that supports cloning/copying, and does
/// *not* indicate validity/existence/ownership.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct InternalFd {
    pub(crate) raw: u32,
}

/// An explicitly-private shared-common element of [`TypedFd`], denoting an owned (non-clonable)
/// token of ownership over a file descriptor.
struct OwnedFd {
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

/// Enable FD support for a particular subsystem conveniently
#[doc(hidden)]
macro_rules! enable_fds_for_subsystem {
    (
        $(@ $($sys_param:ident $(: { $($sys_constraint:tt)* })?),*;)?
        $system:ty;
        $(@ $($ent_param:ident $(: { $($ent_constraint:tt)* })?),*;)?
        $entry:ty;
        $(-> $fd:ident $(<$($fd_param:ident),*>)?;)?
    ) => {
        #[allow(unused, reason = "NOTE(jayb): remove this lint before merging the PR")]
        #[doc(hidden)]
        // This wrapper type exists just to make sure `$entry` itself is not public, but we can
        // still satisfy requirements for `FdEnabledSubsystem`.
        pub struct DescriptorEntry $(< $($ent_param $(: $($ent_constraint)*)?),* >)? {
            entry: $entry,
        }
        impl $(< $($sys_param $(: $($sys_constraint)*)?),* >)? $crate::fd::FdEnabledSubsystem
            for $system
        {
            type Entry = DescriptorEntry $(< $($ent_param),* >)?;
        }
        impl $(< $($ent_param $(: $($ent_constraint)*)?),* >)? $crate::fd::FdEnabledSubsystemEntry
            for DescriptorEntry $(< $($ent_param),* >)?
        {
        }
        impl $(< $($ent_param $(: $($ent_constraint)*)?),* >)? From<$entry>
            for DescriptorEntry $(< $($ent_param),* >)?
        {
            fn from(entry: $entry) -> Self {
                Self { entry }
            }
        }
        $(
            pub type $fd $(<$($fd_param),*>)? = $crate::fd::TypedFd<$system>;
        )?
    };
}
pub(crate) use enable_fds_for_subsystem;
