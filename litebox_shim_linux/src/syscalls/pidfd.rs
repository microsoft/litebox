// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Process file descriptors (`pidfd_open(2)`) backed by broker process handles.

use alloc::sync::Arc;

use litebox::{
    event::{Events, IOPollable, observer::Observer},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    process::{PendingChild, Process, ProcessError},
    sync::RawSyncPrimitivesProvider,
};
use litebox_broker_protocol::{ObjectHandle, ProcessId, fs::FileOpenFlags};
use litebox_common_linux::{FileDescriptorFlags, OFlags, PidfdFlags, errno::Errno};
use litebox_platform::time::TimeProvider;

use super::file::{AnyTypedFd, FilesState, linux_status_flags, status_flags_change};
use crate::{GlobalState, ShimPlatform, Task, UserPtrMut};

pub(crate) struct PidfdSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for PidfdSubsystem<Platform> {
    type Entry = PidFile<Platform>;
}
impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for PidFile<Platform> {}

pub(crate) type PidfdFd<Platform> = TypedFd<PidfdSubsystem<Platform>>;

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
    /// Like Linux, a zombie process can be opened, but a thread other than a main thread cannot.
    /// Thread pidfds (`PIDFD_THREAD`) are unsupported.
    pub(crate) fn sys_pidfd_open(&self, pid: i32, flags: PidfdFlags) -> Result<u32, Errno> {
        if flags.intersects((PidfdFlags::NONBLOCK | PidfdFlags::THREAD).complement()) || pid <= 0 {
            return Err(Errno::EINVAL);
        }
        if flags.contains(PidfdFlags::THREAD) {
            log_unsupported!("pidfd_open with PIDFD_THREAD");
            return Err(Errno::EINVAL);
        }
        // The shared LiteBox instance retains the parent's process identity during `vfork`.
        if self.vfork.borrow().is_some() {
            log_unsupported!("pidfd_open in a vfork child");
            return Err(Errno::EINVAL);
        }
        if pid != self.pid && self.process().has_thread(pid) {
            return Err(Errno::EINVAL);
        }
        let status = if flags.contains(PidfdFlags::NONBLOCK) {
            FileOpenFlags::NONBLOCKING
        } else {
            FileOpenFlags::NONE
        };
        let process = match self
            .global
            .litebox
            .open_process(ProcessId(pid.cast_unsigned()), status)
        {
            Ok(process) => process,
            Err(ProcessError::NoSuchProcess) => {
                return Err(match self.thread_owner(pid) {
                    Ok(_) => Errno::EINVAL,
                    Err(error) => error.into(),
                });
            }
            Err(error) => return Err(error.into()),
        };
        let raw_fd = self.install_pidfd(&self.files.borrow(), process, None)?;
        Ok(u32::try_from(raw_fd).unwrap())
    }

    /// Installs a pidfd for the pending `child` in `files`, as `CLONE_PIDFD` does, stores its
    /// number at `dest`, and returns it.
    pub(crate) fn install_child_pidfd(
        &self,
        files: &FilesState<Platform>,
        child: &PendingChild,
        dest: UserPtrMut<i32>,
    ) -> Result<usize, Errno> {
        let process = self
            .global
            .litebox
            .open_process(child.identity().process_id, FileOpenFlags::NONE)?;
        self.install_pidfd(files, process, Some(dest))
    }

    /// Installs a close-on-exec pidfd for `process` at the lowest free descriptor of `files`,
    /// stores its number at `dest`, if given, and returns it.
    pub(crate) fn install_pidfd(
        &self,
        files: &FilesState<Platform>,
        process: Process<Platform>,
        dest: Option<UserPtrMut<i32>>,
    ) -> Result<usize, Errno> {
        let file = PidFile {
            process: Arc::new(process),
        };
        let mut dt = self.global.litebox.descriptor_table_mut();
        let typed = dt.insert::<PidfdSubsystem<Platform>>(file);
        let old = dt.set_fd_metadata(&typed, FileDescriptorFlags::FD_CLOEXEC);
        assert!(old.is_none());
        drop(dt);
        // The insert, the store, and any rollback share one acquisition of the lock, so no other
        // thread can see or replace the descriptor before the store fails.
        let mut rds = files.raw_descriptor_store.write();
        let raw_fd = match files.insert_raw_fd_locked(&mut rds, typed) {
            Ok(raw_fd) => raw_fd,
            Err(typed) => {
                drop(rds);
                self.remove_and_drop_descriptor(&typed);
                return Err(Errno::EMFILE);
            }
        };
        if let Some(dest) = dest {
            let number = i32::try_from(raw_fd).unwrap();
            if dest.write_at_offset::<Platform>(0, number).is_none() {
                let fd = rds
                    .fd_consume_raw_integer::<PidfdSubsystem<Platform>>(raw_fd)
                    .unwrap();
                drop(rds);
                self.remove_and_drop_descriptor(&fd);
                return Err(Errno::EFAULT);
            }
        }
        Ok(raw_fd)
    }

    /// Closes the pidfd [`Self::install_child_pidfd`] installed at `raw_fd` in this task's
    /// descriptor table for a child that failed to start.
    ///
    /// The other threads must have stayed paused since, so that none could see the pidfd.
    pub(crate) fn remove_child_pidfd(&self, raw_fd: usize) {
        let fd = self
            .files
            .borrow()
            .raw_descriptor_store
            .write()
            .fd_consume_raw_integer::<PidfdSubsystem<Platform>>(raw_fd)
            .expect("the other threads are paused");
        self.remove_and_drop_descriptor(&fd);
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
        let handle = self
            .litebox
            .descriptor_table()
            .entry_handle(fd)
            .ok_or(Errno::EBADF)?;
        handle.with_entry(f)
    }

    /// Adopts a pidfd this process inherited from its parent as `handle`.
    pub(crate) fn adopt_inherited_pidfd(
        &self,
        handle: ObjectHandle,
    ) -> Result<PidfdFd<Platform>, ProcessError> {
        let process = self.litebox.adopt_inherited_process(handle)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert::<PidfdSubsystem<Platform>>(PidFile {
                process: Arc::new(process),
            }))
    }
}

#[cfg(test)]
mod tests {
    use litebox_common_linux::{FcntlArg, FileDescriptorFlags, OFlags, PidfdFlags, errno::Errno};

    #[test]
    fn pidfd_open_names_only_processes() {
        let task = crate::syscalls::tests::init_platform();
        let pid = task.sys_getpid();
        for (pid, flags) in [
            (pid, PidfdFlags::from_bits_retain(1)),
            (pid, PidfdFlags::THREAD),
            (0, PidfdFlags::empty()),
            (-1, PidfdFlags::empty()),
        ] {
            assert_eq!(task.sys_pidfd_open(pid, flags), Err(Errno::EINVAL));
        }
        assert_eq!(
            task.sys_pidfd_open(i32::MAX, PidfdFlags::empty()),
            Err(Errno::ESRCH)
        );
        // Like Linux, only a main thread's ID names a process.
        let sibling = task.clone_for_test().unwrap();
        assert_eq!(
            task.sys_pidfd_open(sibling.tid(), PidfdFlags::empty()),
            Err(Errno::EINVAL)
        );

        let fd = task.sys_pidfd_open(pid, PidfdFlags::NONBLOCK).unwrap();
        let fd = i32::try_from(fd).unwrap();
        assert_eq!(
            task.sys_fcntl(fd, FcntlArg::GETFD),
            Ok(FileDescriptorFlags::FD_CLOEXEC.bits())
        );
        assert_eq!(
            task.sys_fcntl(fd, FcntlArg::GETFL),
            Ok((OFlags::RDWR | OFlags::NONBLOCK).bits())
        );
        let mut buffer = [0u8; 8];
        assert_eq!(task.sys_read(fd, &mut buffer, None), Err(Errno::EINVAL));
        assert_eq!(task.sys_write(fd, &buffer[..], None), Err(Errno::EINVAL));
    }
}
