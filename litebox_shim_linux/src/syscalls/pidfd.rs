// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process file descriptors (`pidfd_open(2)`) backed by broker process handles.

use alloc::sync::Arc;

use litebox::{
    event::{Events, IOPollable, observer::Observer},
    process::{PendingChild, Process, ProcessError},
    sync::RawSyncPrimitivesProvider,
};
use litebox_broker_protocol::{ObjectHandle, ProcessId, fs::FileOpenFlags};
use litebox_common_linux::{OFlags, PidfdFlags, errno::Errno};
use litebox_platform::time::TimeProvider;

use super::file::{AnyTypedFd, linux_status_flags, status_flags_change};
use crate::{GlobalState, ShimPlatform, Task, UserPtrMut};
use litebox_broker_protocol::fd::{FdCreate, FdOperation, FdResponse};
use litebox_broker_protocol::process::OpenProcessHandleRequest;

pub(crate) type PidfdFd<Platform> = PidFile<Platform>;

/// A pidfd, whose process handle and status flags the broker owns, so processes that share it
/// through `fork` see one handle.
///
/// Like Linux, it reports `POLLIN` once the process exits and also `POLLHUP` once it is reaped.
pub(crate) struct PidFile<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    process: Arc<Process<Platform>>,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> PidFile<Platform> {
    /// Returns the `F_GETFL` flags of the pidfd.
    pub(crate) fn get_status_flags(&self) -> Result<OFlags, Errno> {
        linux_status_flags(self.process.get_status_flags()?)
    }

    /// Changes the status flags in `mask` of the pidfd to their values in `flags`, ignoring flags
    /// other than `O_NONBLOCK` and `O_APPEND`.
    pub(crate) fn set_status_flags(&self, mask: OFlags, flags: OFlags) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.process.set_status_flags(mask, flags)?;
        Ok(())
    }

    pub(crate) fn process(&self) -> &Arc<Process<Platform>> {
        &self.process
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for PidFile<Platform> {
    fn check_io_events(&self) -> Events {
        self.process.check_io_events()
    }

    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.process.register_observer(observer, mask);
    }
}

impl<Platform: ShimPlatform> Task<Platform> {
    /// Handle syscall `pidfd_open`.
    ///
    /// Like Linux, a zombie process can be opened, but a thread other than a main thread cannot,
    /// for which Linux 6.15+ fails with `ENOENT` rather than `EINVAL`.
    /// Thread pidfds (`PIDFD_THREAD`) are unsupported.
    pub(crate) fn sys_pidfd_open(&self, pid: i32, flags: PidfdFlags) -> Result<u32, Errno> {
        if flags.intersects((PidfdFlags::NONBLOCK | PidfdFlags::THREAD).complement()) || pid <= 0 {
            return Err(Errno::EINVAL);
        }
        if flags.contains(PidfdFlags::THREAD) {
            log_unsupported!("pidfd_open with PIDFD_THREAD");
            return Err(Errno::EINVAL);
        }
        let pid = self.translate_id_for_requests(pid)?;
        if pid != self.pid && self.process().has_thread(pid) {
            return Err(Errno::ENOENT);
        }
        let status = if flags.contains(PidfdFlags::NONBLOCK) {
            FileOpenFlags::NONBLOCKING
        } else {
            FileOpenFlags::NONE
        };
        Ok(self
            .create_fds(
                FdCreate::Pidfd(OpenProcessHandleRequest {
                    process_id: ProcessId(pid.cast_unsigned()),
                    flags: status,
                }),
                true,
            )?
            .0
            .number)
    }

    /// Installs CLONE_PIDFD in the parent after the child table is copied.
    pub(crate) fn install_child_pidfd(
        &self,
        child: &PendingChild,
        dest: UserPtrMut<i32>,
    ) -> Result<u32, Errno> {
        let files = self.files.borrow().clone();
        let mutation = files.mutation();
        let response = self.fd_request(FdOperation::Create {
            object: FdCreate::Pidfd(OpenProcessHandleRequest {
                process_id: child.identity().process_id,
                flags: FileOpenFlags::NONE,
            }),
            cloexec: true,
        })?;
        let FdResponse::Installed {
            first, revision, ..
        } = response
        else {
            return Err(self
                .cache_installed(&mutation, response)
                .err()
                .unwrap_or(Errno::EIO));
        };
        if dest
            .write_at_offset::<Platform>(0, first.number.cast_signed())
            .is_none()
        {
            self.rollback_fds(&mutation, first.number, None, revision);
            return Err(Errno::EFAULT);
        }
        self.cache_installed(&mutation, response)?;
        Ok(first.number)
    }

    /// Runs `f` on the pidfd at `fd`, failing with `EBADF` if `fd` is not a pidfd.
    pub(crate) fn with_pidfd_at<R>(
        &self,
        fd: i32,
        f: impl FnOnce(&PidFile<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        let AnyTypedFd::Pidfd(fd) = self.typed_fd(fd)? else {
            return Err(Errno::EBADF);
        };
        self.global.with_pidfd(&fd, f)
    }
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    /// Runs `f` on the pidfd at `fd`, without holding the descriptor table.
    pub(crate) fn with_pidfd<R>(
        &self,
        fd: &PidfdFd<Platform>,
        f: impl FnOnce(&PidFile<Platform>) -> Result<R, Errno>,
    ) -> Result<R, Errno> {
        f(fd)
    }

    pub(crate) fn borrow_pidfd(
        &self,
        handle: ObjectHandle,
    ) -> Result<PidfdFd<Platform>, ProcessError> {
        Ok(PidFile {
            process: Arc::new(self.litebox.borrow_fd_process(handle)?),
        })
    }
}
