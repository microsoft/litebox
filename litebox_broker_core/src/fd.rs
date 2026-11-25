// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-process descriptor numbers and descriptor flags.

use alloc::{sync::Arc, vec::Vec};

use litebox_broker_protocol::ObjectHandle;
use litebox_broker_protocol::fd::{DupTarget, FD_LIST_STRIDE, FdInfo, FdKind, MAX_FD_ENTRIES};
use litebox_broker_protocol::process::ResourceKind;
use spin::Mutex;

use crate::readiness::ReadinessSink;
use crate::{BrokerError, BrokerProcess, Result};

/// One descriptor number in a process's table: either an installed file or a reservation.
#[derive(Clone, Copy)]
struct Slot {
    /// Descriptor number; `Table::slots` is kept sorted by it.
    number: u32,
    /// `None` while the number is only reserved by a `PendingFds`.
    file: Option<(ObjectHandle, FdKind)>,
    /// Close-on-exec flag (`FD_CLOEXEC`).
    cloexec: bool,
    /// Table revision at which the file was installed, so `rollback_fds` removes a slot only if
    /// the failed syscall installed it. 0 (never a real revision) marks slots that cannot be
    /// rolled back: reservations and slots inherited across fork.
    installed: u64,
}

impl Slot {
    fn info(self) -> Option<FdInfo> {
        let (handle, kind) = self.file?;
        Some(FdInfo {
            number: self.number,
            handle,
            kind,
        })
    }
}

/// A process's descriptor table.
///
/// Entries are sparse so that dup2 to a large fd costs a single slot. A reservation
/// counts for allocation but is invisible to all other operations, including fork.
#[derive(Default)]
pub(crate) struct FdTable(Mutex<Table>);

/// The lock-protected contents of an `FdTable`.
#[derive(Default)]
struct Table {
    /// Installed and reserved descriptors, sorted by number.
    slots: Vec<Slot>,
    /// Bumped on every change; starts at 0, so 0 is never a returned revision.
    revision: u64,
    /// Set when the process retires; refuses new reservations and pending installs.
    closed: bool,
}

impl Table {
    fn index(&self, number: u32) -> core::result::Result<usize, usize> {
        self.slots.binary_search_by_key(&number, |slot| slot.number)
    }

    fn installed(&self, number: u32) -> Result<usize> {
        self.index(number)
            .ok()
            .filter(|&i| self.slots[i].file.is_some())
            .ok_or(BrokerError::UnknownObject)
    }

    fn lowest(&self, minimum: u32, limit: u64) -> Result<(usize, u32)> {
        let mut i = self.slots.partition_point(|slot| slot.number < minimum);
        let mut number = minimum;
        while self.slots.get(i).is_some_and(|slot| slot.number == number) {
            number += 1;
            i += 1;
        }
        if u64::from(number) >= limit {
            return Err(BrokerError::TooManyOpenFiles);
        }
        Ok((i, number))
    }

    fn reserve(&mut self, count: usize) -> Result<()> {
        if self.closed {
            return Err(BrokerError::PeerClosed);
        }
        if self.slots.len() + count > MAX_FD_ENTRIES {
            return Err(BrokerError::TooManyOpenFiles);
        }
        self.slots
            .try_reserve(count)
            .map_err(|_| BrokerError::OutOfMemory)
    }

    fn changed(&mut self) -> u64 {
        self.revision = self
            .revision
            .checked_add(1)
            .expect("descriptor revision exhausted");
        self.revision
    }

    fn references(&self, handle: ObjectHandle) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.file.is_some_and(|(key, _)| key == handle))
    }
}

/// Space for a create operation, reclaimed on any failure before installation.
pub struct PendingFds<const N: usize> {
    /// The table holding the reservations.
    table: Arc<FdTable>,
    /// The reserved descriptor numbers, in reservation order.
    numbers: [u32; N],
    /// How many of `numbers` are still reserved and must be released on drop; 0 once
    /// installed.
    reserved: usize,
}

impl<const N: usize> Drop for PendingFds<N> {
    fn drop(&mut self) {
        if self.reserved != 0 {
            let mut table = self.table.0.lock();
            for &number in &self.numbers[..self.reserved] {
                let i = table.index(number).expect("reservation disappeared");
                table.slots.remove(i);
            }
        }
    }
}

impl<const N: usize> PendingFds<N> {
    /// Installs the created handles. For a vfork child, move them off the calling association.
    pub fn install(
        mut self,
        caller: &BrokerProcess,
        target: &BrokerProcess,
        mut objects: [(ObjectHandle, FdKind); N],
        readiness: &Arc<dyn ReadinessSink>,
    ) -> Result<([FdInfo; N], u64)> {
        if caller.key() != target.key() {
            let duplicates =
                caller.duplicate_object_references_to(&objects.map(|(handle, _)| handle), target);
            for (handle, _) in objects {
                let _ = caller.close_object_reference(handle);
            }
            for (object, handle) in objects.iter_mut().zip(duplicates?) {
                object.0 = handle;
            }
        }
        let handles = objects.map(|(handle, _)| handle);
        if let Err(error) = target.register_fd_readiness(&handles, readiness) {
            for handle in handles {
                let _ = target.close_object_reference(handle);
            }
            return Err(error);
        }
        let mut table = self.table.0.lock();
        let mark = if table.closed {
            Err(BrokerError::PeerClosed)
        } else {
            target.mark_fd_handles(&handles)
        };
        if let Err(error) = mark {
            drop(table);
            for handle in handles {
                let _ = target.close_object_reference(handle);
            }
            return Err(error);
        }
        let installed = table.changed();
        let entries = core::array::from_fn(|i| {
            let number = self.numbers[i];
            let index = table.index(number).expect("reservation disappeared");
            let (handle, kind) = objects[i];
            table.slots[index].file = Some((handle, kind));
            table.slots[index].installed = installed;
            FdInfo {
                number,
                handle,
                kind,
            }
        });
        self.reserved = 0;
        Ok((entries, installed))
    }
}

impl BrokerProcess {
    /// Duplicates a transferable object for installation in a descriptor table.
    pub fn duplicate_fd_object(&self, handle: ObjectHandle) -> Result<(ObjectHandle, FdKind)> {
        use litebox_broker_protocol::ObjectKind;
        let (object, rights) = self.object_reference(handle)?;
        let kind = match object.read().transferred_kind() {
            Some(ObjectKind::File) => FdKind::File,
            Some(ObjectKind::PipeReadEnd) => FdKind::PipeRead,
            Some(ObjectKind::PipeWriteEnd) => FdKind::PipeWrite,
            Some(ObjectKind::UnixSocket(ty)) => FdKind::Unix(ty),
            Some(ObjectKind::InetSocket(ty)) => FdKind::Inet(ty),
            Some(ObjectKind::VsockSocket) => FdKind::Vsock,
            Some(ObjectKind::EventCounter) => FdKind::Event,
            Some(ObjectKind::Timer) => FdKind::Timer,
            Some(ObjectKind::ReadinessQueue) => FdKind::Epoll,
            Some(ObjectKind::Process) => FdKind::Pidfd,
            None => return Err(BrokerError::UnsupportedOperation),
        };
        Ok((
            self.create_object_reference_with_rights(object, rights)?,
            kind,
        ))
    }

    fn fd_limit(&self) -> Result<u64> {
        Ok(self
            .get_resource_limit(self.id(), ResourceKind::OpenFiles)?
            .soft())
    }

    /// Reserves descriptor numbers before performing a potentially side-effecting create.
    pub fn reserve_fds<const N: usize>(&self, cloexec: bool) -> Result<PendingFds<N>> {
        let mut pending = PendingFds {
            table: self.files.clone(),
            numbers: [0; N],
            reserved: 0,
        };
        let mut table = self.files.0.lock();
        let limit = self.fd_limit()?;
        table.reserve(N)?;
        let mut minimum = 0;
        for number in &mut pending.numbers {
            let (i, next) = table.lowest(minimum, limit)?;
            table.slots.insert(
                i,
                Slot {
                    number: next,
                    file: None,
                    cloexec,
                    installed: 0,
                },
            );
            *number = next;
            pending.reserved += 1;
            minimum = next + 1;
        }
        drop(table);
        Ok(pending)
    }

    /// Finds the current object behind a descriptor.
    pub fn fd_info(&self, number: u32) -> Result<FdInfo> {
        let table = self.files.0.lock();
        table.slots[table.installed(number)?]
            .info()
            .ok_or(BrokerError::Internal)
    }

    /// Copies installed descriptors and duplicates each unique object handle into `child`.
    pub(crate) fn copy_fds_to(&self, child: &Self) -> Result<()> {
        let table = self.files.0.lock();
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(table.slots.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        slots.extend(
            table
                .slots
                .iter()
                .filter(|slot| slot.file.is_some())
                .copied(),
        );
        let mut handles = Vec::new();
        handles
            .try_reserve_exact(slots.len())
            .map_err(|_| BrokerError::OutOfMemory)?;
        handles.extend(slots.iter().map(|slot| slot.file.unwrap().0));
        handles.sort_unstable_by_key(|handle| handle.0);
        handles.dedup();
        let duplicates = self.duplicate_object_references_to(&handles, child)?;
        child.mark_fd_handles(&duplicates)?;
        for slot in &mut slots {
            let (handle, _) = slot.file.as_mut().unwrap();
            *handle = duplicates[handles
                .binary_search_by_key(&handle.0, |key| key.0)
                .unwrap()];
            slot.installed = 0;
        }
        child.files.0.lock().slots = slots;
        Ok(())
    }

    /// Installs a duplicate or atomically replaces the requested descriptor.
    pub fn duplicate_fd(&self, fd: u32, target: DupTarget, cloexec: bool) -> Result<(FdInfo, u64)> {
        let mut table = self.files.0.lock();
        let limit = self.fd_limit()?;
        if matches!(target, DupTarget::Exact { number, distinct: true } if fd == number) {
            return Err(BrokerError::InvalidArgument);
        }
        let source = table.slots[table.installed(fd)?];
        let (number, index, replace) = match target {
            DupTarget::Exact { number, .. } => {
                if number == fd {
                    return Ok((
                        source.info().ok_or(BrokerError::Internal)?,
                        source.installed,
                    ));
                }
                if u64::from(number) >= limit {
                    return Err(BrokerError::UnknownObject);
                }
                match table.index(number) {
                    Ok(i) if table.slots[i].file.is_none() => {
                        return Err(BrokerError::DescriptorBusy);
                    }
                    Ok(i) => (number, i, true),
                    Err(i) => (number, i, false),
                }
            }
            DupTarget::AtLeast(min) if u64::from(min) >= limit => {
                return Err(BrokerError::InvalidArgument);
            }
            DupTarget::AtLeast(_) | DupTarget::Lowest => {
                let min = if let DupTarget::AtLeast(min) = target {
                    min
                } else {
                    0
                };
                let (i, number) = table.lowest(min, limit)?;
                (number, i, false)
            }
        };
        let slot = Slot {
            number,
            file: source.file,
            cloexec,
            installed: table.changed(),
        };
        let released = if replace {
            let old = core::mem::replace(&mut table.slots[index], slot)
                .file
                .ok_or(BrokerError::Internal)?
                .0;
            (!table.references(old)).then_some(old)
        } else {
            table.reserve(1)?;
            table.slots.insert(index, slot);
            None
        };
        let revision = slot.installed;
        drop(table);
        if let Some(handle) = released {
            self.close_fd_handle(handle);
        }
        Ok((slot.info().ok_or(BrokerError::Internal)?, revision))
    }

    /// Closes one descriptor.
    // XXX: Shim views borrow the handle, so closing it here retires readiness under a thread
    // blocked on this fd, which then never wakes. Hold an object reference for each in-flight
    // operation instead.
    pub fn close_fd(&self, number: u32) -> Result<u64> {
        let mut table = self.files.0.lock();
        let i = table.installed(number)?;
        let (handle, _) = table.slots.remove(i).file.ok_or(BrokerError::Internal)?;
        let release = !table.references(handle);
        let revision = table.changed();
        drop(table);
        if release {
            self.close_fd_handle(handle);
        }
        Ok(revision)
    }

    /// Rolls back only the slots installed by the failed syscall.
    pub fn rollback_fds(
        &self,
        first: u32,
        second: Option<u32>,
        installed: u64,
    ) -> Result<(u64, bool, bool)> {
        if installed == 0 {
            return Err(BrokerError::InvalidArgument);
        }
        let mut table = self.files.0.lock();
        let [first, second] = [Some(first), second].map(|number| {
            let i = table.installed(number?).ok()?;
            if table.slots[i].installed == installed {
                table.slots.remove(i).file.map(|(handle, _)| handle)
            } else {
                None
            }
        });
        let revision = table.changed();
        let release =
            [first, second].map(|handle| handle.filter(|&handle| !table.references(handle)));
        drop(table);
        for (i, handle) in release.into_iter().enumerate() {
            if let Some(handle) = handle
                && (i == 0 || first != Some(handle))
            {
                self.close_fd_handle(handle);
            }
        }
        Ok((revision, first.is_some(), second.is_some()))
    }

    /// Reads the close-on-exec flag, or sets it and returns its new value.
    pub fn fd_cloexec(&self, fd: u32, set: Option<bool>) -> Result<bool> {
        let mut table = self.files.0.lock();
        let i = table.installed(fd)?;
        let slot = &mut table.slots[i];
        if let Some(cloexec) = set {
            slot.cloexec = cloexec;
        }
        Ok(slot.cloexec)
    }

    /// Closes or marks a range. At exec commit only marked descriptors are closed.
    pub fn sweep_fds(&self, first: u32, last: u32, mark: bool, exec: bool) -> Result<u64> {
        if first > last {
            return Err(BrokerError::InvalidArgument);
        }
        let mut table = self.files.0.lock();
        let selected = |slot: &Slot| {
            slot.file.is_some() && (first..=last).contains(&slot.number) && (!exec || slot.cloexec)
        };
        if mark {
            for slot in table.slots.iter_mut().filter(|slot| selected(slot)) {
                slot.cloexec = true;
            }
            return Ok(table.revision);
        }
        let mut dropped = Vec::new();
        dropped
            .try_reserve_exact(table.slots.iter().filter(|slot| selected(slot)).count())
            .map_err(|_| BrokerError::OutOfMemory)?;
        dropped.extend(
            table
                .slots
                .extract_if(.., |slot| selected(slot))
                .filter_map(|slot| slot.file.map(|(handle, _)| handle)),
        );
        dropped.sort_unstable_by_key(|handle| handle.0);
        dropped.dedup();
        dropped.retain(|&handle| !table.references(handle));
        let revision = table.changed();
        drop(table);
        for handle in dropped {
            self.close_fd_handle(handle);
        }
        Ok(revision)
    }

    pub(crate) fn retire_fds(&self) {
        let mut table = self.files.0.lock();
        table.closed = true;
        // An in-flight create retains its reservation until it sees the closed table.
        table.slots.retain(|slot| slot.file.is_none());
        table.slots.shrink_to_fit();
    }

    /// Encodes a snapshot in the caller's shared buffer format.
    pub fn list_fds(&self, capacity: usize) -> Result<(u64, Vec<u8>)> {
        let table = self.files.0.lock();
        let size = table
            .slots
            .iter()
            .filter(|slot| slot.file.is_some())
            .count()
            * FD_LIST_STRIDE;
        if size > capacity {
            return Err(BrokerError::InvalidArgument);
        }
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(size)
            .map_err(|_| BrokerError::OutOfMemory)?;
        Ok((
            table.revision,
            FdInfo::encode_list(table.slots.iter().filter_map(|slot| slot.info()), bytes),
        ))
    }
}
