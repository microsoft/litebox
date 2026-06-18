// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! File descriptors used in LiteBox

#![expect(
    dead_code,
    reason = "still under development, remove before merging PR"
)]

use alloc::sync::{Arc, Weak};
use alloc::vec;
use alloc::vec::Vec;
use core::any::TypeId;
use core::marker::PhantomData;
use core::sync::atomic::AtomicBool;
use thiserror::Error;

use crate::sync::{RawSyncPrimitivesProvider, RwLock};
use crate::utilities::anymap::AnyMap;

#[cfg(test)]
mod tests;

/// Storage of file descriptors and their entries.
pub struct Descriptors<Platform: RawSyncPrimitivesProvider> {
    entries: Vec<Option<IndividualEntry<Platform>>>,
    next_object_id: u64,
}

/// Stable identifier for a shared descriptor object.
///
/// This corresponds to the underlying open-file-description style object that
/// may be referenced by multiple duplicated or fork-inherited file-descriptor
/// tokens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DescriptorObjectId(u64);

/// Closed set of fd-owning subsystems.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SubsystemKind {
    /// Filesystem descriptors.
    Fs,
    /// Network socket descriptors.
    Net,
    /// Pipe descriptors.
    Pipes,
    /// Eventfd and timerfd descriptors.
    Eventfd,
    /// Epoll descriptors.
    Epoll,
    /// Unix-domain socket descriptors.
    Unix,
    /// Host passthrough fd descriptors.
    HostPassthroughFd,
    /// Broker pipe descriptors.
    BrokerPipe,
    /// Broker socketpair descriptors.
    BrokerSocketPair,
    /// Broker AF_UNIX datagram socket descriptors.
    BrokerSocketDgram,
    /// Broker AF_UNIX seqpacket socket descriptors.
    BrokerSocketSeqPacket,
    /// Broker AF_UNIX named stream socket descriptors.
    BrokerUnixStream,
    /// Broker pty descriptors.
    BrokerPty,
    /// Signalfd descriptors.
    Signalfd,
    /// Inotify descriptors.
    Inotify,
    /// Broker TCP listener descriptors.
    BrokerInetListener,
    /// Broker UDP datagram descriptors.
    BrokerInetDgram,
    /// Broker raw IPv4 socket descriptors.
    BrokerInetRaw,
    /// Broker TCP connection descriptors.
    BrokerTcpConn,
}

impl DescriptorObjectId {
    /// Returns the raw numeric value.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl<Platform: RawSyncPrimitivesProvider> Descriptors<Platform> {
    /// Explicitly crate-internal: Create a new empty descriptor table.
    ///
    /// This is expected to be invoked only by [`crate::LiteBox`]'s creation method, and should not
    /// be invoked anywhere else in the codebase.
    pub(crate) fn new_from_litebox_creation() -> Self {
        Self {
            entries: vec![],
            next_object_id: 1,
        }
    }

    fn allocate_object_id(&mut self) -> DescriptorObjectId {
        let object_id = DescriptorObjectId(self.next_object_id);
        self.next_object_id = self
            .next_object_id
            .checked_add(1)
            .expect("descriptor object ids should not overflow");
        object_id
    }

    /// Insert `entry` into the descriptor table, returning an `OwnedFd` to this entry.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    #[must_use]
    pub fn insert<Subsystem: FdEnabledSubsystem>(
        &mut self,
        entry: impl Into<Subsystem::Entry>,
    ) -> TypedFd<Subsystem> {
        let object_id = self.allocate_object_id();
        let entry = DescriptorEntry {
            entry: alloc::boxed::Box::new(entry.into()),
            subsystem_kind: Subsystem::KIND,
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
        let old = self.entries[idx].replace(IndividualEntry::new(
            Arc::new(RwLock::new(entry)),
            object_id,
        ));
        assert!(old.is_none());
        TypedFd {
            _phantom: PhantomData,
            x: OwnedFd::new(idx, object_id),
        }
    }

    /// Duplicate an entry given only its raw index, returning a new [`OwnedFd`]
    /// that independently tracks its closed state.
    ///
    /// This is used by [`RawDescriptorStorage::clone_for_fork`] so that parent
    /// and child processes get independent `OwnedFd` instances that share the
    /// underlying file description (via `Arc`).
    ///
    /// Per-fd metadata (e.g. `FD_CLOEXEC`) is cloned from the source entry,
    /// matching POSIX fork semantics where the child inherits the parent's
    /// per-fd flags.
    ///
    /// Returns `None` if the fd is already closed.
    pub(crate) fn duplicate_raw_fd(&mut self, raw: &OwnedFd) -> Option<OwnedFd> {
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        let (shared_entry, metadata, object_id) = {
            let src = self.entries[raw.as_usize()?].as_ref().unwrap();
            src.x.read().entry.on_dup();
            (Arc::clone(&src.x), src.metadata.clone(), src.object_id)
        };
        let new_ind_entry = IndividualEntry {
            x: shared_entry,
            metadata,
            object_id,
        };
        let old = self.entries[idx].replace(new_ind_entry);
        assert!(old.is_none());
        Some(OwnedFd::new(idx, object_id))
    }

    /// Create a duplicate of the provided `fd`.
    ///
    /// This newly-created FD shares all behavior with the existing FD, including (for example)
    /// offsets. Any metadata stored via [`Self::set_entry_metadata`] is (as expected) maintained as
    /// aliased metadata at the new FD. However, any metadata that was stored via
    /// [`Self::set_fd_metadata`] is **not** duplicated; if you want that data to be copied over to
    /// the new entry, you must copy it over yourself.
    ///
    /// If the fd has already been closed (potentially on a different thread), this duplication will
    /// fail and will return `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panic is impossible due to type invariants"
    )]
    pub fn duplicate<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<TypedFd<Subsystem>> {
        let idx = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.entries.push(None);
                self.entries.len() - 1
            });
        let (shared_entry, object_id) = {
            let src = self.entries[fd.x.as_usize()?].as_ref().unwrap();
            src.x.read().entry.on_dup();
            (Arc::clone(&src.x), src.object_id)
        };
        let new_ind_entry = IndividualEntry::new(shared_entry, object_id);
        let old = self.entries[idx].replace(new_ind_entry);
        assert!(old.is_none());
        Some(TypedFd {
            _phantom: PhantomData,
            x: OwnedFd::new(idx, object_id),
        })
    }

    /// Removes the entry at `fd`, closing out the file descriptor.
    ///
    /// Returns the descriptor entry if it is unique (i.e., it was not duplicated, or all duplicates
    /// have been cleared out).
    ///
    /// If the `fd` was already closed out, then (obviously) it does not return an entry.
    pub fn remove<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<Subsystem::Entry> {
        let Some(old) = self.entries[fd.x.as_usize()?].take() else {
            unreachable!();
        };
        old.x.read().entry.on_close();
        fd.x.mark_as_closed();
        Arc::into_inner(old.x)
            .map(RwLock::into_inner)
            .map(DescriptorEntry::into_subsystem_entry::<Subsystem>)
    }

    /// Close the provided `fd`, removing the entry from the descriptor table.
    ///
    /// This method takes a closure `can_close_immediately` that is called with the entry to determine
    /// whether the file descriptor can be closed immediately. This allows the caller to implement
    /// custom logic (e.g., checking for pending data) before allowing the close to proceed.
    ///
    /// Unlike the previous `close_and_duplicate_if_shared`, this always frees the slot. When other
    /// references exist (from `dup` or `fork`), the slot is released without socket teardown. The
    /// socket remains alive via the other reference's slot.
    ///
    /// The `Deferred` result is only returned when this is the last reference AND `can_close_immediately`
    /// returns false (pending data). In that case, the entry stays in the slot for later polling.
    pub(crate) fn close_and_remove<
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&Subsystem::Entry) -> bool,
    >(
        &mut self,
        fd: &TypedFd<Subsystem>,
        can_close_immediately: F,
    ) -> Option<CloseResult<Subsystem>> {
        let idx = fd.x.as_usize()?;
        let entry = self.entries[idx].as_ref().unwrap();

        // Only check pending data when we're the last reference.
        // If other refs exist (dup or fork), they'll service the socket after we release our slot.
        if Arc::strong_count(&entry.x) == 1
            && !can_close_immediately(entry.x.read().as_subsystem::<Subsystem>())
        {
            // Last ref, pending data — keep entry in slot for close_pending_sockets to poll.
            return Some(CloseResult::Deferred);
        }

        // Always remove the slot.
        let old = self.entries[idx].take().unwrap();
        old.x.read().entry.on_close();
        fd.x.mark_as_closed();

        match Arc::into_inner(old.x) {
            Some(rwlock) => {
                // Last reference — extract entry for teardown.
                let entry = RwLock::into_inner(rwlock).into_subsystem_entry::<Subsystem>();
                Some(CloseResult::Closed(entry))
            }
            None => {
                // Other references exist (dup or fork). Slot freed, done.
                Some(CloseResult::Released)
            }
        }
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

    /// Iterator over all live descriptors and their unchecked subsystem tag/type pair.
    pub fn iter_with_kind(&self) -> impl Iterator<Item = (u32, SubsystemKind, TypeId)> + '_ {
        self.entries.iter().enumerate().filter_map(|(i, entry)| {
            entry.as_ref().map(|e| {
                let entry = e.read();
                (
                    i.try_into().unwrap(),
                    entry.subsystem_kind,
                    (entry.entry.as_ref() as &dyn core::any::Any).type_id(),
                )
            })
        })
    }

    /// An iterator of descriptors and (mutable) entries for a subsystem
    ///
    /// Note: each of the entries take locks, thus should not be held on to for too long, in order
    /// to prevent dead-locks.
    pub(crate) fn iter_mut<Subsystem: FdEnabledSubsystem>(
        &self,
    ) -> impl Iterator<
        Item = (
            InternalFd,
            impl core::ops::DerefMut<Target = Subsystem::Entry>,
        ),
    > {
        self.entries.iter().enumerate().filter_map(|(i, entry)| {
            entry.as_ref().and_then(|e| {
                if !e.read().matches_subsystem::<Subsystem>() {
                    return None;
                }
                let entry = e.write();
                assert!(entry.matches_subsystem::<Subsystem>());
                Some((
                    InternalFd {
                        raw: i.try_into().unwrap(),
                    },
                    crate::sync::RwLockWriteGuard::map(entry, |e| {
                        e.as_subsystem_mut::<Subsystem>()
                    }),
                ))
            })
        })
    }

    /// Use the entry at `fd` as read-only.
    ///
    /// If the `fd` has been closed, then skips applying `f` and returns `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    pub fn with_entry<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let entry = self.entries[fd.x.as_usize()?].as_ref().unwrap().read();
        Some(f(entry.as_subsystem::<Subsystem>()))
    }

    /// Use the entry at `fd` as mutably.
    ///
    /// If the `fd` has been closed, then skips applying `f` and returns `None`.
    #[expect(
        clippy::missing_panics_doc,
        reason = "panics impossible due to type invariants"
    )]
    pub fn with_entry_mut<Subsystem, F, R>(&self, fd: &TypedFd<Subsystem>, f: F) -> Option<R>
    where
        Subsystem: FdEnabledSubsystem,
        F: FnOnce(&mut Subsystem::Entry) -> R,
    {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let mut entry = self.entries[fd.x.as_usize()?].as_ref().unwrap().write();
        Some(f(entry.as_subsystem_mut::<Subsystem>()))
    }

    /// Obtain a handle to the underlying entry for the `fd`.
    ///
    /// Similar to [`Self::with_entry`], except it does not require maintaining access to the table.
    pub fn entry_handle<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<EntryHandle<Platform, Subsystem>> {
        // Since the typed FD should not have been created unless we had the correct subsystem in
        // the first place, none of this should panic---if it does, someone has done a bad cast
        // somewhere.
        let entry = self.entries[fd.x.as_usize()?].as_ref()?;
        Some(EntryHandle {
            entry: Arc::clone(&entry.x),
            object_id: entry.object_id,
            _phantom: PhantomData,
        })
    }

    /// Handles to all currently alive entries in a subsystem.
    pub fn entry_handles<Subsystem: FdEnabledSubsystem>(
        &self,
    ) -> impl Iterator<Item = EntryHandle<Platform, Subsystem>> + '_ {
        self.entries.iter().filter_map(|entry| {
            let entry = entry.as_ref()?;
            let guard = entry.read();
            if !guard.matches_subsystem::<Subsystem>() {
                return None;
            }
            drop(guard);
            Some(EntryHandle {
                entry: entry.x.clone(),
                object_id: entry.object_id,
                _phantom: PhantomData,
            })
        })
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
    ) -> Option<impl core::ops::Deref<Target = Subsystem::Entry> + use<'_, Platform, Subsystem>>
    {
        Some(crate::sync::RwLockReadGuard::map(
            self.entries[fd.x.as_usize()?].as_ref().unwrap().read(),
            |e| e.as_subsystem::<Subsystem>(),
        ))
    }

    /// Get the entry at `fd`, mutably.
    ///
    /// Note: this grabs a lock, thus the result should not be held for too long, to prevent
    /// deadlocks. Prefer using [`Self::with_entry_mut`] when possible, to make life easier.
    pub(crate) fn get_entry_mut<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: &TypedFd<Subsystem>,
    ) -> Option<impl core::ops::DerefMut<Target = Subsystem::Entry> + use<'_, Platform, Subsystem>>
    {
        Some(crate::sync::RwLockWriteGuard::map(
            self.entries[fd.x.as_usize()?].as_ref().unwrap().write(),
            |e| e.as_subsystem_mut::<Subsystem>(),
        ))
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
        let ind_entry = self.entries[fd.x.as_usize().ok_or(MetadataError::ClosedFd)?]
            .as_ref()
            .unwrap();
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
        let ind_entry = self.entries[fd.x.as_usize().ok_or(MetadataError::ClosedFd)?]
            .as_mut()
            .unwrap();
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
    ///
    /// Silently drops the store if the FD has been closed out.
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
        T: core::any::Any + Clone + Send + Sync,
    {
        self.entries[fd.x.as_usize()?]
            .as_ref()
            .unwrap()
            .x
            .write()
            .metadata
            .insert(metadata)
    }

    /// Store arbitrary metadata into a file descriptor.
    ///
    /// Such metadata is specific to the current fd and is NOT shared with other open fds to the
    /// same entry. See the similar [`Self::set_entry_metadata`] which aliases metadata over all fds
    /// opened for the same entry.
    ///
    /// Silently drops the store if the FD has been closed out.
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
        T: core::any::Any + Clone + Send + Sync,
    {
        self.entries[fd.x.as_usize()?]
            .as_mut()
            .unwrap()
            .metadata
            .insert(metadata)
    }
}

/// A handle to a descriptor entry (via [`Descriptors::entry_handle`]) that can be used without
/// maintaining access to the descriptor table itself.
pub struct EntryHandle<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem> {
    entry: Arc<RwLock<Platform, DescriptorEntry>>,
    object_id: DescriptorObjectId,
    _phantom: PhantomData<Subsystem>,
}
impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem> Clone
    for EntryHandle<Platform, Subsystem>
{
    fn clone(&self) -> Self {
        Self {
            entry: Arc::clone(&self.entry),
            object_id: self.object_id,
            _phantom: PhantomData,
        }
    }
}
impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem>
    EntryHandle<Platform, Subsystem>
{
    /// Returns the shared descriptor-object identity.
    pub fn object_id(&self) -> DescriptorObjectId {
        self.object_id
    }

    pub fn identity_addr(&self) -> usize {
        Arc::as_ptr(&self.entry).addr()
    }

    pub fn with_entry<R>(&self, f: impl FnOnce(&Subsystem::Entry) -> R) -> R {
        f(self.entry.read().as_subsystem::<Subsystem>())
    }

    pub fn with_entry_mut<R>(&self, f: impl FnOnce(&mut Subsystem::Entry) -> R) -> R {
        f(self.entry.write().as_subsystem_mut::<Subsystem>())
    }

    pub fn downgrade(&self) -> WeakEntryHandle<Platform, Subsystem> {
        WeakEntryHandle {
            entry: Arc::downgrade(&self.entry),
            object_id: self.object_id,
            _phantom: PhantomData,
        }
    }
}

pub struct WeakEntryHandle<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem> {
    entry: Weak<RwLock<Platform, DescriptorEntry>>,
    object_id: DescriptorObjectId,
    _phantom: PhantomData<Subsystem>,
}
impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem> Clone
    for WeakEntryHandle<Platform, Subsystem>
{
    fn clone(&self) -> Self {
        Self {
            entry: self.entry.clone(),
            object_id: self.object_id,
            _phantom: PhantomData,
        }
    }
}
impl<Platform: RawSyncPrimitivesProvider, Subsystem: FdEnabledSubsystem>
    WeakEntryHandle<Platform, Subsystem>
{
    /// Returns the shared descriptor-object identity.
    pub fn object_id(&self) -> DescriptorObjectId {
        self.object_id
    }

    pub fn identity_addr(&self) -> usize {
        self.entry.as_ptr().addr()
    }

    pub fn upgrade(&self) -> Option<EntryHandle<Platform, Subsystem>> {
        Some(EntryHandle {
            entry: self.entry.upgrade()?,
            object_id: self.object_id,
            _phantom: PhantomData,
        })
    }
}

/// Result of a [`Descriptors::close_and_remove`] operation
pub(crate) enum CloseResult<Subsystem: FdEnabledSubsystem> {
    /// The FD was the last reference and has been closed, returning the entry for teardown
    Closed(Subsystem::Entry),
    /// The slot was freed, but other references (dup or fork) still exist — no teardown needed
    Released,
    /// The FD was unique but couldn't be closed immediately (e.g., due to pending data)
    Deferred,
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

/// An opaque token representing an fd duplicated for inter-process delivery
/// (e.g. via `SCM_RIGHTS`). Create one with
/// [`RawDescriptorStorage::duplicate_for_passing`] and install it on the
/// receiving side with [`RawDescriptorStorage::insert_passed_fd`].
pub struct PassedFd {
    owned: OwnedFd,
    subsystem_kind: SubsystemKind,
}

impl PassedFd {
    /// Returns the subsystem kind for the fd being passed.
    #[must_use]
    pub fn subsystem_kind(&self) -> SubsystemKind {
        self.subsystem_kind
    }
}

struct StoredFd {
    x: Arc<OwnedFd>,
    subsystem_kind: SubsystemKind,
}

impl Clone for StoredFd {
    fn clone(&self) -> Self {
        Self {
            x: Arc::clone(&self.x),
            subsystem_kind: self.subsystem_kind,
        }
    }
}
impl StoredFd {
    fn new<Subsystem: FdEnabledSubsystem>(fd: TypedFd<Subsystem>) -> Self {
        Self {
            x: Arc::new(fd.x),
            subsystem_kind: Subsystem::KIND,
        }
    }
    #[must_use]
    fn matches_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> bool {
        self.subsystem_kind == Subsystem::KIND
    }
}

impl RawDescriptorStorage {
    #[expect(clippy::new_without_default)]
    /// Create a new raw descriptor store.
    pub fn new() -> Self {
        Self { stored_fds: vec![] }
    }

    /// Clone the descriptor storage for `fork()`.
    ///
    /// Each stored fd is duplicated in the global `Descriptors` table so that
    /// the child gets an independent `OwnedFd` (with its own `closed` flag).
    /// The underlying file descriptions are shared via `Arc`, matching POSIX
    /// shared-file-description semantics after fork.
    ///
    /// # Panics
    ///
    /// Panics if any stored fd has already been closed in `global_dt`.
    #[must_use]
    pub fn clone_for_fork<Platform: RawSyncPrimitivesProvider>(
        &self,
        global_dt: &mut Descriptors<Platform>,
    ) -> Self {
        Self {
            stored_fds: self
                .stored_fds
                .iter()
                .map(|slot| {
                    slot.as_ref().map(|stored| {
                        let new_owned = global_dt
                            .duplicate_raw_fd(&stored.x)
                            .expect("fd should not be closed during fork");
                        StoredFd {
                            x: Arc::new(new_owned),
                            subsystem_kind: stored.subsystem_kind,
                        }
                    })
                })
                .collect(),
        }
    }

    /// Duplicate a stored fd for inter-process passing (e.g. `SCM_RIGHTS`).
    ///
    /// Creates a new entry in the global descriptor table that shares the same
    /// underlying file description as the fd at `raw_fd`. Returns a
    /// [`PassedFd`] token that can be installed in another process's raw
    /// descriptor store via [`Self::insert_passed_fd`].
    ///
    /// Returns `None` if `raw_fd` is not occupied or the underlying owned fd
    /// has already been closed.
    pub fn duplicate_for_passing<Platform: RawSyncPrimitivesProvider>(
        &self,
        raw_fd: usize,
        global_dt: &mut Descriptors<Platform>,
    ) -> Option<PassedFd> {
        let stored = self.stored_fds.get(raw_fd)?.as_ref()?;
        let new_owned = global_dt.duplicate_raw_fd(&stored.x)?;
        Some(PassedFd {
            owned: new_owned,
            subsystem_kind: stored.subsystem_kind,
        })
    }

    /// Install an fd received via inter-process passing (e.g. `SCM_RIGHTS`).
    ///
    /// The caller supplies a [`PassedFd`] token (obtained from
    /// [`Self::duplicate_for_passing`]). The fd is placed in the first
    /// available slot and its raw integer is returned.
    ///
    /// # Panics
    ///
    /// Panics if the selected slot is unexpectedly occupied.
    pub fn insert_passed_fd(&mut self, passed: PassedFd) -> usize {
        let raw_fd = self
            .stored_fds
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                self.stored_fds.push(None);
                self.stored_fds.len() - 1
            });
        let stored = StoredFd {
            x: Arc::new(passed.owned),
            subsystem_kind: passed.subsystem_kind,
        };
        let old = self.stored_fds[raw_fd].replace(stored);
        assert!(old.is_none());
        raw_fd
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

    /// Get the typed FD for the raw integer value of the `fd`.
    ///
    /// To fully remove this FD from see [`Self::fd_consume_raw_integer`].
    pub fn fd_from_raw_integer<Subsystem: FdEnabledSubsystem>(
        &self,
        fd: usize,
    ) -> Result<Arc<TypedFd<Subsystem>>, ErrRawIntFd> {
        self.typed_fd_at_raw_1(fd)
    }

    /// Obtain the typed FD for the raw integer value of the `fd`, "consuming" the raw integer.
    ///
    /// Since this operation "consumes" the raw integer, future [`Self::fd_from_raw_integer`] might
    /// not refer to this file descriptor.
    ///
    /// You almost definitely want [`Self::fd_from_raw_integer`] instead, and should only use this
    /// if you really know you want to consume the descriptor.
    pub fn fd_consume_raw_integer<Subsystem: FdEnabledSubsystem>(
        &mut self,
        fd: usize,
    ) -> Result<Arc<TypedFd<Subsystem>>, ErrRawIntFd> {
        let ret = self.fd_from_raw_integer(fd)?;
        let underlying = self.stored_fds[fd].take();
        debug_assert!(underlying.is_some());
        drop(underlying);
        Ok(ret)
    }

    /// Check if there is a valid FD at the raw integer value `fd`.
    ///
    /// This function is entirely subsystem-irrelevant. If you want to check against a subsystem,
    /// you might wish to use [`Self::fd_from_raw_integer`].
    #[must_use]
    pub fn is_alive(&self, fd: usize) -> bool {
        self.stored_fds.get(fd).is_some_and(Option::is_some)
    }

    /// Returns an iterator over raw integer indices that are currently alive (i.e., occupied).
    pub fn iter_alive(&self) -> impl Iterator<Item = usize> + '_ {
        self.stored_fds
            .iter()
            .enumerate()
            .filter_map(|(i, slot)| slot.as_ref().map(|_| i))
    }
}

macro_rules! multi_subsystem_generic {
    ($ident_f:ident, $ident_i:ident, $($f:ident $subsystem:ident),+ $(,)?) => {
        /// Invoke the corresponding function that matches the subsystem.
        ///
        /// Equivalent versions of this function exist at differing number of subsystems.
        fn $ident_f<R, $($subsystem),+>(
            &self,
            fd: usize,
            $(
                $f: impl FnOnce(Arc<TypedFd<$subsystem>>) -> R
            ),+
        ) -> Result<R, ErrRawIntFd>
        where
            $($subsystem: FdEnabledSubsystem),+
        {
            let Some(Some(stored_fd)) = self.stored_fds.get(fd) else {
                return Err(ErrRawIntFd::NotFound);
            };
            $(
                if stored_fd.matches_subsystem::<$subsystem>() {
                    let typed_fd: Arc<TypedFd<$subsystem>> = {
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
                        //   - Thus, `OwnedFd` and `TypedFd` are effectively the same type, and
                        //     thus are safely castable.
                        //
                        //   - `Arc::from_raw`'s safety documentation requires the standard safe
                        //     castability constraints between the two.
                        unsafe { Arc::from_raw(fd.cast()) }
                    };
                    return Ok($f(typed_fd));
                }
            )+
                Err(ErrRawIntFd::InvalidSubsystem)
        }

        /// Get a conversion of the typed FD for any of the N subsystems for the raw integer
        /// value of the `fd`.
        ///
        /// Equivalent versions of this function exist at differing number of subsystems.
        pub fn $ident_i<R, $($subsystem),+>(
            &self,
            fd: usize,
        ) -> Result<R, ErrRawIntFd>
        where
            $($subsystem: FdEnabledSubsystem, R: From<Arc<TypedFd<$subsystem>>>),+
        {
            self.$ident_f(fd, $(
                |x: Arc<TypedFd<$subsystem>>| R::from(x)
            ),+)
        }
    };
}

impl RawDescriptorStorage {
    multi_subsystem_generic! {invoke_matching_subsystem_1, typed_fd_at_raw_1, f1 S1}
    multi_subsystem_generic! {invoke_matching_subsystem_2, typed_fd_at_raw_2, f1 S1, f2 S2}
    multi_subsystem_generic! {invoke_matching_subsystem_3, typed_fd_at_raw_3, f1 S1, f2 S2, f3 S3}
    multi_subsystem_generic! {invoke_matching_subsystem_4, typed_fd_at_raw_4, f1 S1, f2 S2, f3 S3, f4 S4}
}

/// A LiteBox subsystem that support having file descriptors.
pub trait FdEnabledSubsystem: Sized {
    /// Closed subsystem tag used for exhaustive descriptor dispatch.
    const KIND: SubsystemKind;

    /// The per-FD entry type stored in the descriptor table for this subsystem
    type Entry: FdEnabledSubsystemEntry + 'static;
}

/// A per-FD entry stored in the descriptor table for a specific [`FdEnabledSubsystem`]
pub trait FdEnabledSubsystemEntry: Send + Sync + core::any::Any {
    /// Called when this entry is duplicated (e.g. via `dup`/`dup2`/`fork`).
    /// Subsystems that maintain reference counts (PTY open counts, pipe sender
    /// counts) should increment them here.
    fn on_dup(&self) {}

    /// Called when a file descriptor referencing this entry is closed.
    /// Subsystems that maintain reference counts should decrement them here
    /// and fire any resulting notifications (e.g. HUP on last PTY close).
    fn on_close(&self) {}
}

/// Possible errors from [`RawDescriptorStorage::fd_from_raw_integer`] and
/// [`RawDescriptorStorage::fd_consume_raw_integer`].
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
    #[error("fd has been closed")]
    ClosedFd,
}

/// A module-internal fd-specific individual entry
struct IndividualEntry<Platform: RawSyncPrimitivesProvider> {
    x: Arc<RwLock<Platform, DescriptorEntry>>,
    object_id: DescriptorObjectId,
    metadata: AnyMap,
}
impl<Platform: RawSyncPrimitivesProvider> core::ops::Deref for IndividualEntry<Platform> {
    type Target = Arc<RwLock<Platform, DescriptorEntry>>;
    fn deref(&self) -> &Self::Target {
        &self.x
    }
}
impl<Platform: RawSyncPrimitivesProvider> IndividualEntry<Platform> {
    fn new(x: Arc<RwLock<Platform, DescriptorEntry>>, object_id: DescriptorObjectId) -> Self {
        Self {
            x,
            object_id,
            metadata: AnyMap::new(),
        }
    }
}

/// A crate-internal entry for a descriptor.
pub(crate) struct DescriptorEntry {
    entry: alloc::boxed::Box<dyn FdEnabledSubsystemEntry>,
    subsystem_kind: SubsystemKind,
    metadata: AnyMap,
}

impl DescriptorEntry {
    /// Check if this entry matches the specified subsystem
    #[must_use]
    fn matches_subsystem<Subsystem: FdEnabledSubsystem>(&self) -> bool {
        self.subsystem_kind == Subsystem::KIND
            && (self.entry.as_ref() as &dyn core::any::Any).type_id()
                == TypeId::of::<Subsystem::Entry>()
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
    // Invariant in `Subsystem`: <https://doc.rust-lang.org/nomicon/phantom-data.html#table-of-phantomdata-patterns>
    _phantom: PhantomData<fn(Subsystem) -> Subsystem>,
    x: OwnedFd,
}

impl<Subsystem: FdEnabledSubsystem> TypedFd<Subsystem> {
    /// Get the "internal FD"
    pub(crate) fn as_internal_fd(&self) -> InternalFd {
        assert!(!self.x.is_closed());
        InternalFd { raw: self.x.raw }
    }

    /// Returns the shared descriptor-object identity for this file descriptor.
    pub fn object_id(&self) -> DescriptorObjectId {
        self.x.object_id()
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
///
/// Note: this indicates ownership over the descriptor itself, but not necessarily the underlying
/// entry, since there might be duplicates to the underlying entry.
pub(crate) struct OwnedFd {
    raw: u32,
    object_id: DescriptorObjectId,
    closed: AtomicBool,
}

impl OwnedFd {
    /// Produce a new owned token from a raw index
    ///
    /// Panics if outside the u32 range
    pub(crate) fn new(raw: usize, object_id: DescriptorObjectId) -> Self {
        Self {
            raw: raw.try_into().unwrap(),
            object_id,
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) fn object_id(&self) -> DescriptorObjectId {
        self.object_id
    }

    /// Check if it is closed
    pub(crate) fn is_closed(&self) -> bool {
        self.closed.load(core::sync::atomic::Ordering::SeqCst)
    }

    /// Mark it as closed
    pub(crate) fn mark_as_closed(&self) {
        let was_closed = self
            .closed
            .fetch_or(true, core::sync::atomic::Ordering::SeqCst);
        assert!(!was_closed);
    }

    /// Obtain the raw index it was created with if it has not been closed.
    ///
    /// Returns `None` if it has already been closed.
    pub(crate) fn as_usize(&self) -> Option<usize> {
        if self.is_closed() {
            return None;
        }
        let v: usize = self.raw.try_into().unwrap();
        Some(v)
    }
}

impl Drop for OwnedFd {
    fn drop(&mut self) {
        if self.is_closed() {
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
        $kind:expr;
        $(-> $fd:ident $(<$($fd_param:ident),*>)?;)?
    ) => {
        #[doc(hidden)]
        // This wrapper type exists just to make sure `$entry` itself is not public, but we can
        // still satisfy requirements for `FdEnabledSubsystem`.
        pub struct DescriptorEntry $(< $($ent_param $(: $($ent_constraint)*)?),* >)? {
            entry: $entry,
        }
        impl $(< $($sys_param $(: $($sys_constraint)*)?),* >)? $crate::fd::FdEnabledSubsystem
            for $system
        {
            const KIND: $crate::fd::SubsystemKind = $kind;

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
