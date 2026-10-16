// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux ABI glue for the generic LiteBox pipe subsystem.
//!
//! `litebox::pipes` owns the pipe endpoint and readiness mechanics, and the
//! broker owns each end's status flags. This module owns Linux-specific
//! presentation: `pipe2` flags, `fcntl` status flags, and errno mapping.

use alloc::sync::{Arc, Weak};
use core::num::NonZero;

use litebox::{
    event::{Events, IOPollable, observer::Observer, wait::WaitContext},
    fd::{FdEnabledSubsystem, FdEnabledSubsystemEntry, TypedFd},
    pipes::{self, HalfPipeType},
};
use litebox_broker_protocol::{
    ObjectHandle,
    fs::{FileMode as Mode, FileOpenFlags},
};
use litebox_common_linux::{FileDescriptorFlags, InodeType, OFlags, errno::Errno};

use super::file::{linux_status_flags, status_flags_change};
use crate::{GlobalState, ShimPlatform};

const DEFAULT_PIPE_BUF_SIZE: usize = 64 * 1024;

pub(crate) struct PipeSubsystem<Platform: ShimPlatform>(core::marker::PhantomData<Platform>);
impl<Platform: ShimPlatform> FdEnabledSubsystem for PipeSubsystem<Platform> {
    type Entry = PipeEnd<Platform>;
}

impl<Platform: ShimPlatform> FdEnabledSubsystemEntry for PipeEnd<Platform> {}

pub(crate) type PipeFd<Platform> = TypedFd<PipeSubsystem<Platform>>;

/// A pipe end descriptor's open file description.
pub(crate) struct PipeEnd<Platform: ShimPlatform> {
    end: Arc<pipes::PipeEnd<Platform>>,
}

impl<Platform: ShimPlatform> From<pipes::PipeEnd<Platform>> for PipeEnd<Platform> {
    fn from(end: pipes::PipeEnd<Platform>) -> Self {
        Self { end: Arc::new(end) }
    }
}

impl<Platform: ShimPlatform> IOPollable for PipeEnd<Platform> {
    fn register_observer(&self, observer: Weak<dyn Observer<Events>>, mask: Events) {
        self.end.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        self.end.check_io_events()
    }
}

/// Both ends of a freshly created Linux pipe, which the caller must either
/// install as raw descriptors or remove from the descriptor table.
pub(crate) struct LinuxPipeEnds<Platform: ShimPlatform> {
    pub(crate) reader: PipeFd<Platform>,
    pub(crate) writer: PipeFd<Platform>,
}

impl<Platform: ShimPlatform> GlobalState<Platform> {
    pub(crate) fn create_linux_pipe(
        &self,
        flags: OFlags,
    ) -> Result<LinuxPipeEnds<Platform>, Errno> {
        if flags.intersects((OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::DIRECT).complement()) {
            return Err(Errno::EINVAL);
        }
        if flags.contains(OFlags::DIRECT) {
            todo!("O_DIRECT not supported");
        }
        let status_flags = if flags.contains(OFlags::NONBLOCK) {
            FileOpenFlags::NONBLOCKING
        } else {
            FileOpenFlags::NONE
        };

        let (writer, reader) = self.litebox.create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            status_flags,
            // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
            NonZero::new(4096),
        )?;

        let mut dt = self.litebox.descriptor_table_mut();
        let writer = dt.insert::<PipeSubsystem<Platform>>(writer);
        let reader = dt.insert::<PipeSubsystem<Platform>>(reader);
        if flags.contains(OFlags::CLOEXEC) {
            let None = dt.set_fd_metadata(&writer, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
            let None = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
        }

        Ok(LinuxPipeEnds { reader, writer })
    }

    /// Returns the pipe end at `fd`, without holding the descriptor table.
    pub(crate) fn pipe_end(
        &self,
        fd: &PipeFd<Platform>,
    ) -> Result<Arc<pipes::PipeEnd<Platform>>, Errno> {
        self.litebox
            .descriptor_table()
            .with_entry(fd, |pipe| Arc::clone(&pipe.end))
            .ok_or(Errno::EBADF)
    }

    pub(crate) fn read_linux_pipe(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        Ok(self.pipe_end(fd)?.read(cx, buf)?)
    }

    pub(crate) fn write_linux_pipe(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &[u8],
    ) -> Result<usize, Errno> {
        Ok(self.pipe_end(fd)?.write(cx, buf)?)
    }

    /// Returns the `F_GETFL` flags of the pipe end at `fd`.
    pub(crate) fn linux_pipe_status_flags(&self, fd: &PipeFd<Platform>) -> Result<OFlags, Errno> {
        linux_status_flags(self.pipe_end(fd)?.get_status_flags()?)
    }

    /// Changes the status flags in `mask` of the pipe end at `fd` to their values in `flags`,
    /// ignoring flags other than `O_NONBLOCK` and `O_APPEND`.
    pub(crate) fn set_linux_pipe_status_flags(
        &self,
        fd: &PipeFd<Platform>,
        mask: OFlags,
        flags: OFlags,
    ) -> Result<(), Errno> {
        let (mask, flags) = status_flags_change(mask, flags);
        self.pipe_end(fd)?.set_status_flags(mask, flags)?;
        Ok(())
    }

    pub(crate) fn linux_pipe_mode_bits(&self, fd: &PipeFd<Platform>) -> Result<u32, Errno> {
        let read_write_mode = match self.pipe_end(fd)?.endpoint_type() {
            HalfPipeType::SenderHalf => Mode::WUSR,
            HalfPipeType::ReceiverHalf => Mode::RUSR,
        };
        Ok(u32::from(read_write_mode.bits()) | InodeType::NamedPipe as u32)
    }

    /// Adopts a pipe end this runner inherited across `execve`.
    pub(crate) fn adopt_inherited_linux_pipe(
        &self,
        handle: ObjectHandle,
        endpoint_type: HalfPipeType,
    ) -> Result<PipeFd<Platform>, litebox::process::ProcessError> {
        let end = self.litebox.adopt_inherited_pipe(handle, endpoint_type)?;
        Ok(self
            .litebox
            .descriptor_table_mut()
            .insert::<PipeSubsystem<Platform>>(end))
    }
}
