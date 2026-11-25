// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use alloc::collections::BTreeMap;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use litebox_broker_protocol::error::ErrorCode;
use litebox_broker_protocol::fd::{
    FdCreate, FdInfo, FdKind, FdOperation, FdPeer, FdRequest, FdResponse,
};
use litebox_broker_protocol::{ObjectHandle, ProcessId};
use litebox_common_linux::errno::Errno;

use super::file::AnyTypedFd;
use super::file::File;
use super::{
    epoll::EpollFile, eventfd::EventFile, inet::InetSocket, pidfd::PidFile, pipe::PipeEnd,
    timerfd::TimerFile, unix::UnixSocket, vsock::VsockSocket,
};
use crate::{GlobalState, ShimPlatform, Task};

// A late duplicate reply may be the only descriptor left for an object whose old
// typed view is still in use by another syscall. Reuse its readiness registration.
enum WeakFd<P: ShimPlatform> {
    File(Weak<File<P>>),
    Inet(Weak<InetSocket<P>>),
    Pipe(Weak<PipeEnd<P>>),
    Eventfd(Weak<EventFile<P>>),
    Epoll(Weak<EpollFile<P>>),
    Unix(Weak<UnixSocket<P>>),
    Timerfd(Weak<TimerFile<P>>),
    Vsock(Weak<VsockSocket<P>>),
    Pidfd(Weak<PidFile<P>>),
}

macro_rules! fd_variants {
    ($value:expr, $from:ident, $to:ident, $map:expr) => {
        match $value {
            $from::File(fd) => $map(fd).map($to::File),
            $from::Inet(fd) => $map(fd).map($to::Inet),
            $from::Pipe(fd) => $map(fd).map($to::Pipe),
            $from::Eventfd(fd) => $map(fd).map($to::Eventfd),
            $from::Epoll(fd) => $map(fd).map($to::Epoll),
            $from::Unix(fd) => $map(fd).map($to::Unix),
            $from::Timerfd(fd) => $map(fd).map($to::Timerfd),
            $from::Vsock(fd) => $map(fd).map($to::Vsock),
            $from::Pidfd(fd) => $map(fd).map($to::Pidfd),
        }
    };
}

impl<P: ShimPlatform> WeakFd<P> {
    fn new(fd: &AnyTypedFd<P>) -> Self {
        fd_variants!(fd, AnyTypedFd, WeakFd, |fd| Some(Arc::downgrade(fd))).unwrap()
    }

    fn upgrade(&self) -> Option<AnyTypedFd<P>> {
        fd_variants!(self, WeakFd, AnyTypedFd, Weak::upgrade)
    }
}

pub(crate) struct FilesState<P: ShimPlatform> {
    cache: litebox::sync::RwLock<P, Cache<P>>,
}

struct Cache<P: ShimPlatform> {
    slots: BTreeMap<u32, (u64, ObjectHandle, AnyTypedFd<P>)>,
    objects: BTreeMap<ObjectHandle, WeakFd<P>>,
    // Broker replies may apply out of order; retain invalidations until all overlapping
    // in-flight requests have applied theirs.
    // XXX: Add concurrency tests for out-of-order replies (close vs. reuse, dup2 vs. install,
    // close_range vs. a late install) unless this cache is gone first.
    removed: Vec<(u32, u32, u64)>,
    active: usize,
}

impl<P: ShimPlatform> FilesState<P> {
    pub(crate) fn new() -> Self {
        Self {
            cache: litebox::sync::RwLock::new(Cache {
                slots: BTreeMap::new(),
                objects: BTreeMap::new(),
                removed: Vec::new(),
                active: 0,
            }),
        }
    }

    pub(crate) fn typed_fd(&self, raw: i32) -> Result<AnyTypedFd<P>, Errno> {
        self.typed_fd_from_raw(usize::try_from(raw).map_err(|_| Errno::EBADF)?)
    }

    pub(crate) fn typed_fd_from_raw(&self, raw: usize) -> Result<AnyTypedFd<P>, Errno> {
        let number = u32::try_from(raw).map_err(|_| Errno::EBADF)?;
        self.cache
            .read()
            .slots
            .get(&number)
            .map(|(_, _, fd)| fd.clone())
            .ok_or(Errno::EBADF)
    }

    pub(super) fn transferable_handle(&self, raw: i32) -> Result<ObjectHandle, Errno> {
        let number = u32::try_from(raw).map_err(|_| Errno::EBADF)?;
        let cache = self.cache.read();
        let (_, handle, fd) = cache.slots.get(&number).ok_or(Errno::EBADF)?;
        if matches!(fd, AnyTypedFd::Unix(_)) {
            return Err(Errno::EOPNOTSUPP);
        }
        Ok(*handle)
    }

    pub(crate) fn mutation(&self) -> Mutation<'_, P> {
        self.cache.write().active += 1;
        Mutation(self)
    }

    pub(crate) fn from_broker(
        global: &GlobalState<P>,
        pending_child: Option<ProcessId>,
    ) -> Result<Self, Errno> {
        let (revision, entries) = global
            .litebox
            .list_fds(pending_child, false)
            .map_err(fd_errno)?;
        let files = Self::new();
        let mutation = files.mutation();
        for entry in entries {
            mutation.install(global, revision, entry)?;
        }
        drop(mutation);
        Ok(files)
    }
}

pub(crate) struct Mutation<'a, P: ShimPlatform>(&'a FilesState<P>);

impl<P: ShimPlatform> Drop for Mutation<'_, P> {
    fn drop(&mut self) {
        let mut cache = self.0.cache.write();
        cache.active -= 1;
        if cache.active == 0 {
            cache.removed.clear();
        }
        if cache.objects.len() > cache.slots.len().saturating_mul(2).max(64) {
            cache.objects.retain(|_, fd| fd.upgrade().is_some());
        }
    }
}

impl<P: ShimPlatform> Mutation<'_, P> {
    pub(crate) fn install(
        &self,
        global: &GlobalState<P>,
        revision: u64,
        info: FdInfo,
    ) -> Result<Option<AnyTypedFd<P>>, Errno> {
        let mut cache = self.0.cache.write();
        if cache
            .slots
            .get(&info.number)
            .is_some_and(|(newer, _, _)| *newer >= revision)
            || cache.removed.iter().any(|&(first, last, newer)| {
                newer >= revision && (first..=last).contains(&info.number)
            })
        {
            return Ok(None);
        }
        let fd = if let Some(fd) = cache.objects.get(&info.handle).and_then(WeakFd::upgrade) {
            fd
        } else {
            let fd = global.borrow_fd(info)?;
            cache.objects.insert(info.handle, WeakFd::new(&fd));
            fd
        };
        let replaced = cache.slots.insert(info.number, (revision, info.handle, fd));
        Ok(replaced
            .filter(|(_, handle, _)| {
                !cache
                    .slots
                    .values()
                    .any(|(_, current, _)| current == handle)
            })
            .map(|(_, _, fd)| fd))
    }

    pub(crate) fn remove(&self, first: u32, last: u32, revision: u64) -> Vec<AnyTypedFd<P>> {
        let mut cache = self.0.cache.write();
        cache.removed.push((first, last, revision));
        let numbers: Vec<_> = cache
            .slots
            .range(first..=last)
            .filter_map(|(&number, (installed, _, _))| (*installed < revision).then_some(number))
            .collect();
        numbers
            .into_iter()
            .filter_map(|number| cache.slots.remove(&number).map(|(_, _, fd)| fd))
            .collect()
    }

    pub(crate) fn keep(&self, entries: &[FdInfo]) -> Vec<AnyTypedFd<P>> {
        let mut cache = self.0.cache.write();
        let numbers: Vec<_> = cache
            .slots
            .keys()
            .copied()
            .filter(|number| {
                entries
                    .binary_search_by_key(number, |entry| entry.number)
                    .is_err()
            })
            .collect();
        numbers
            .into_iter()
            .filter_map(|number| cache.slots.remove(&number).map(|(_, _, fd)| fd))
            .collect()
    }
}

impl<P: ShimPlatform> GlobalState<P> {
    fn borrow_fd(&self, info: FdInfo) -> Result<AnyTypedFd<P>, Errno> {
        let handle = info.handle;
        Ok(match info.kind {
            FdKind::File => AnyTypedFd::File(Arc::new(self.litebox.borrow_fd_file(handle)?.into())),
            FdKind::PipeRead | FdKind::PipeWrite => AnyTypedFd::Pipe(Arc::new(
                self.borrow_pipe(handle, info.kind == FdKind::PipeRead)?,
            )),
            FdKind::Inet(kind) => AnyTypedFd::Inet(Arc::new(
                self.litebox.borrow_fd_inet_socket(handle, kind)?.into(),
            )),
            FdKind::Unix(kind) => AnyTypedFd::Unix(Arc::new(
                self.litebox.borrow_fd_unix_socket(handle, kind)?.into(),
            )),
            FdKind::Vsock => AnyTypedFd::Vsock(Arc::new(
                self.litebox.borrow_fd_vsock_socket(handle)?.into(),
            )),
            FdKind::Event => AnyTypedFd::Eventfd(Arc::new(self.borrow_eventfd(handle)?)),
            FdKind::Timer => AnyTypedFd::Timerfd(Arc::new(self.borrow_timerfd(handle)?)),
            FdKind::Epoll => AnyTypedFd::Epoll(Arc::new(self.borrow_epoll(handle)?)),
            FdKind::Pidfd => AnyTypedFd::Pidfd(Arc::new(self.borrow_pidfd(handle)?)),
        })
    }
}

impl<P: ShimPlatform> Task<P> {
    pub(super) fn pending_fd_child(&self) -> Option<ProcessId> {
        self.vfork
            .borrow()
            .as_ref()
            .map(|state| state.child.identity().process_id)
    }

    pub(super) fn fd_request(&self, operation: FdOperation) -> Result<FdResponse, Errno> {
        self.global
            .litebox
            .fd_request(FdRequest {
                pending_child: self.pending_fd_child(),
                operation,
            })
            .map_err(fd_errno)
    }

    pub(super) fn create_fds(
        &self,
        object: FdCreate,
        cloexec: bool,
    ) -> Result<(FdInfo, Option<FdInfo>, Option<FdPeer>), Errno> {
        let files = self.files.borrow().clone();
        let mutation = files.mutation();
        let response = self.fd_request(FdOperation::Create { object, cloexec })?;
        self.cache_installed(&mutation, response)
    }

    pub(super) fn create_fd_pair(
        &self,
        object: FdCreate,
        cloexec: bool,
        publish: impl FnOnce(u32, u32) -> Result<(), Errno>,
    ) -> Result<(u32, u32), Errno> {
        let files = self.files.borrow().clone();
        let mutation = files.mutation();
        let response = self.fd_request(FdOperation::Create { object, cloexec })?;
        let FdResponse::Installed {
            first,
            second: Some(second),
            revision,
            ..
        } = response
        else {
            return self
                .cache_installed(&mutation, response)
                .and(Err(Errno::EIO));
        };
        if let Err(error) = publish(first.number, second.number) {
            self.rollback_fds(&mutation, first.number, Some(second.number), revision);
            return Err(error);
        }
        self.cache_installed(&mutation, response)?;
        Ok((first.number, second.number))
    }

    pub(super) fn rollback_fds(
        &self,
        mutation: &Mutation<'_, P>,
        first: u32,
        second: Option<u32>,
        installed: u64,
    ) {
        // XXX: Unlike Linux, fds are installed before guest copyout and rolled back on failure,
        // so other threads can briefly observe them. Needs reserve-then-install.
        if let Ok(FdResponse::RolledBack {
            revision,
            first: removed_first,
            second: removed_second,
        }) = self.fd_request(FdOperation::Rollback {
            first,
            second,
            installed,
        }) {
            if removed_first {
                self.finalize_closed(mutation.remove(first, first, revision));
            }
            if let Some(second) = second.filter(|_| removed_second) {
                self.finalize_closed(mutation.remove(second, second, revision));
            }
        }
    }

    pub(super) fn cache_installed(
        &self,
        mutation: &Mutation<'_, P>,
        response: FdResponse,
    ) -> Result<(FdInfo, Option<FdInfo>, Option<FdPeer>), Errno> {
        match response {
            FdResponse::Installed {
                first,
                second,
                peer,
                revision,
            } => {
                self.finalize_closed(mutation.install(&self.global, revision, first)?);
                if let Some(second) = second {
                    self.finalize_closed(mutation.install(&self.global, revision, second)?);
                }
                Ok((first, second, peer))
            }
            FdResponse::PidfdMissing { thread } => {
                Err(if thread { Errno::ENOENT } else { Errno::ESRCH })
            }
            FdResponse::FileFailed(error) => {
                Err(litebox::fs::errors::OpenError::from(error).into())
            }
            FdResponse::SocketFailed(error) => {
                Err(litebox::inet_socket::errors::SocketAsyncError::from(error).into())
            }
            FdResponse::UnixFailed(error) => {
                Err(litebox::unix_socket::errors::UnixSocketError::Socket(error).into())
            }
            _ => Err(Errno::EIO),
        }
    }

    pub(super) fn finalize_closed(&self, fds: impl IntoIterator<Item = AnyTypedFd<P>>) {
        for fd in fds {
            if let AnyTypedFd::File(fd) = fd {
                self.finalize_elf_patch(fd);
            }
        }
    }

    pub(crate) fn commit_exec_fds(&self) -> Result<(), Errno> {
        let files = self.files.borrow().clone();
        let mutation = files.mutation();
        let (_, entries) = self
            .global
            .litebox
            .list_fds(self.pending_fd_child(), true)
            .map_err(fd_errno)?;
        self.finalize_closed(mutation.keep(&entries));
        Ok(())
    }
}

pub(crate) fn fd_errno(error: ErrorCode) -> Errno {
    match error {
        ErrorCode::UnknownObject | ErrorCode::InvalidRights => Errno::EBADF,
        ErrorCode::TooManyOpenFiles => Errno::EMFILE,
        ErrorCode::InvalidArgument => Errno::EINVAL,
        ErrorCode::DescriptorBusy => Errno::EBUSY,
        ErrorCode::WouldBlock | ErrorCode::NonBlockingWouldBlock => Errno::EAGAIN,
        ErrorCode::OutOfMemory => Errno::ENOMEM,
        // XXX: Only socket creation means ENOBUFS; pipe2 wants ENFILE, eventfd/timerfd ENOMEM,
        // pidfd_open EAGAIN. Map per syscall.
        ErrorCode::ResourceExhausted => Errno::ENOBUFS,
        ErrorCode::PolicyDenied => Errno::EACCES,
        ErrorCode::UnsupportedOperation => Errno::EOPNOTSUPP,
        _ => Errno::EIO,
    }
}
