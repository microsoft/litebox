//! File descriptors used in LiteBox

#![expect(
    dead_code,
    reason = "still under development, remove before merging PR"
)]

use alloc::sync::{Arc, Weak};
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
pub struct Descriptors<Platform: RawSyncPrimitivesProvider> {
    litebox: LiteBox<Platform>,
    entries: Vec<Option<IndividualEntry<Platform>>>,
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
        let old = self.entries[idx].replace(IndividualEntry::new(Arc::new(
            self.litebox.sync().new_rwlock(entry),
        )));
        assert!(old.is_none());
        TypedFd {
            _phantom: PhantomData,
            x: OwnedFd::new(idx),
        }
    }

    /// Create a duplicate of the provided `fd`.
    ///
    /// This newly-created FD shares all behavior with the existing FD, including (for example)
    /// offsets. Any metadata stored via [`Self::set_entry_metadata`] is (as expected) maintained as
    /// aliased metadata at the new FD. However, any metadata that was stored via
    /// [`Self::set_fd_metadata`] is **not** duplicated; if you want that data to be copied over to
    /// the new entry, you must copy it over yourself.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panic is impossible due to type invariants"
    )]
    pub fn duplicate<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: &TypedFd<Subsystem>,
    ) -> TypedFd<Subsystem> {
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        let new_ind_entry = IndividualEntry::new(Arc::clone(
            &self.entries[fd.x.as_usize()].as_ref().unwrap().x,
        ));
        let old = self.entries[idx].replace(new_ind_entry);
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

/// Safe(r) conversions between safely-typed file descriptors and unsafely-typed integers.
///
/// This particular object is also able to turn safely-typed file descriptors to/from unsafely-typed
/// integers, with a reasonable amount of safety---this will not be able to check for "ABA" style
/// issues, but will at least prevent using a descriptor for an unintended subsystem at the point of
/// conversion.
pub struct RawDescriptorStorage {
    /// Stored FDs are used to provide raw integer values in a safer way.
    stored_fds: Vec<Option<StoredFd>>,
}

struct StoredFd {
    x: Arc<OwnedFd>,
    subsystem_entry_type_id: core::any::TypeId,
}
impl StoredFd {
    fn new<Subsystem: FdEnabledSubsystem>(fd: TypedFd<Subsystem>) -> Self {
        Self {
            x: Arc::new(fd.x),
            subsystem_entry_type_id: core::any::TypeId::of::<Subsystem::Entry>(),
        }
    }
    #[must_use]
    fn matches_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> bool {
        self.subsystem_entry_type_id == core::any::TypeId::of::<Subsystem::Entry>()
    }
}

impl RawDescriptorStorage {
    #[expect(clippy::new_without_default)]
    /// Create a new raw descriptor store.
    pub fn new() -> Self {
        Self { stored_fds: vec![] }
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
        let ret = self
            .stored_fds
            .iter()
            .position(Option::is_none)
            .unwrap_or(self.stored_fds.len());
        let success = self.fd_into_specific_raw_integer(fd, ret);
        assert!(success);
        ret
    }

    /// Store the provided `fd` at the provided _specific_ raw integer FD.
    ///
    /// This is similar to [`Self::fd_into_raw_integer`] except that it specifies a specific FD to
    /// be stored into.
    ///
    /// Will return with `true` iff it succeeds (i.e., nothing else was using that raw integer FD).
    /// If you want to replace a used slot, you must first consume that slot via
    /// [`Self::fd_consume_raw_integer`].
    #[must_use]
    #[expect(
        clippy::missing_panics_doc,
        reason = "not guaranteed as an API-level guarantee, but instead as a defensive panic to re-consider implementation if we hit it"
    )]
    pub fn fd_into_specific_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: TypedFd<Subsystem>,
        raw_fd: usize,
    ) -> bool {
        // TODO(jayb): Should we be storing things via a HashMap to make sure this operation cannot
        // be too expensive if someone tries to store into a large raw FD?
        //
        // If this assertion failure is hit in practice, we might need to be more defensive via the
        // HashMap, rather than just silently allow big growth
        assert!(
            raw_fd < self.stored_fds.len() + 100,
            "explicit upper bound restriction for now; see implementation details"
        );
        if self.stored_fds.get(raw_fd).is_some_and(Option::is_some) {
            // There's already something at this slot.
            return false;
        }
        if raw_fd >= self.stored_fds.len() {
            self.stored_fds.resize_with(raw_fd + 1, || None);
        }
        let old = self.stored_fds[raw_fd].replace(StoredFd::new(fd));
        assert!(old.is_none());
        true
    }

    /// Borrow the typed FD for the raw integer value of the `fd`.
    ///
    /// Importantly, users of this function should **not** store an upgrade of the `Weak`.
    ///
    /// This operation is mainly aimed at usage in the scenario where there is only a "short
    /// duration" between generation of the typed FD and its use. Raw integers have no long-term
    /// meaning, and can switch subsystems over time. All this is captured in the usage of `Weak` as
    /// the return. If the underlying FD got consumed away, then it becomes non-upgradable.
    ///
    /// Returns `Ok` iff the `fd` exists and is for the correct subsystem.
    ///
    /// To fully remove this FD from the system to make it available to consume, see
    /// [`Self::fd_consume_raw_integer`].
    pub fn fd_from_raw_integer<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: usize,
    ) -> Result<Weak<TypedFd<Subsystem>>, ErrRawIntFd> {
        let Some(Some(stored_fd)) = self.stored_fds.get(fd) else {
            return Err(ErrRawIntFd::NotFound);
        };
        if !stored_fd.matches_subsystem::<Subsystem>() {
            return Err(ErrRawIntFd::InvalidSubsystem);
        }

        let typed_fd: Arc<TypedFd<Subsystem>> = {
            let fd: Arc<OwnedFd> = Arc::clone(&stored_fd.x);
            let fd: *const OwnedFd = Arc::into_raw(fd);
            // SAFETY: We are effectively converting an `Arc<OwnedFd>` to an
            // `Arc<TypedFd<Subsystem>>`.
            //
            // This is safe because:
            //
            //   - `TypedFd` is a `#[repr(transparent)]` wrapper on `OwnedFd`.
            //
            //   - We just confirmed that it is of the correct subsystem.
            //
            //   - Thus, `OwnedFd` and `TypedFd` are effectively the same type, and thus are safely
            //     castable.
            //
            //   - `Arc::from_raw`'s safety documentation requires the standard safe castability
            //     constraints between the two.
            unsafe { Arc::from_raw(fd.cast()) }
        };

        Ok(Arc::downgrade(&typed_fd))
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
            Some(stored_fd) => {
                if !stored_fd.matches_subsystem::<Subsystem>() {
                    return Err(ErrRawIntFd::InvalidSubsystem);
                }
            }
        }
        let Some(sfd) = stored_fd.take() else {
            return Err(ErrRawIntFd::NotFound);
        };
        match Arc::try_unwrap(sfd.x) {
            Ok(owned_fd) => Ok(TypedFd {
                _phantom: PhantomData,
                x: owned_fd,
            }),
            Err(owned_fd) => {
                // Seems like it is unconsumable due to ongoing usage (there is some `Weak` from
                // `fd_from_raw_integer` that has been upgraded). We should let the user know that there
                // is ongoing usage.
                let None = stored_fd.replace(StoredFd {
                    x: owned_fd,
                    subsystem_entry_type_id: sfd.subsystem_entry_type_id,
                }) else {
                    unreachable!()
                };
                Err(ErrRawIntFd::CurrentlyUnconsumable)
            }
        }
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

/// Possible errors from [`RawDescriptorStorage::fd_from_raw_integer`] and
/// [`RawDescriptorStorage::fd_consume_raw_integer`].
#[derive(Error, Debug)]
pub enum ErrRawIntFd {
    #[error("no such file descriptor found")]
    NotFound,
    #[error("fd for invalid subsystem")]
    InvalidSubsystem,
    #[error("could not consume due to ongoing FD usage")]
    CurrentlyUnconsumable,
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
    fn new(x: Arc<RwLock<Platform, DescriptorEntry>>) -> Self {
        Self {
            x,
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
