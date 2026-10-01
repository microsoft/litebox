// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Linux ABI glue for the generic LiteBox pipe subsystem.
//!
//! `litebox::pipes` owns the pipe endpoint and readiness mechanics, and the
//! broker owns each end's status flags. This module owns Linux-specific
//! presentation: `pipe2` flags, `fcntl` status flags, and errno mapping.

use core::num::NonZero;

use litebox::{
    event::wait::WaitContext,
    pipes::{HalfPipeType, PipeFd},
};
use litebox_broker_protocol::{
    ObjectHandle,
    fs::{FileMode as Mode, FileOpenFlags},
};
use litebox_common_linux::{
    FileDescriptorFlags, InodeType, OFlags, errno::Errno, program_startup::InheritedFdKind,
};

use super::file::status_flags_change;
use crate::{GlobalState, ShimPlatform};

const DEFAULT_PIPE_BUF_SIZE: usize = 64 * 1024;

/// Both ends of a freshly created Linux pipe.
///
/// `PipeFd` does not release the pipe on `Drop`; ends must either be inserted
/// into the fd table or explicitly released via [`GlobalState::close_linux_pipe`].
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

        let (writer, reader) = self.pipes.create_pipe(
            DEFAULT_PIPE_BUF_SIZE,
            status_flags,
            // See `man 7 pipe` for `PIPE_BUF`. On Linux, this is 4096.
            NonZero::new(4096),
        )?;

        if flags.contains(OFlags::CLOEXEC) {
            let mut dt = self.litebox.descriptor_table_mut();
            let None = dt.set_fd_metadata(&writer, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
            let None = dt.set_fd_metadata(&reader, FileDescriptorFlags::FD_CLOEXEC) else {
                unreachable!()
            };
        }

        Ok(LinuxPipeEnds { reader, writer })
    }

    pub(crate) fn close_linux_pipe(&self, fd: &PipeFd<Platform>) -> Result<(), Errno> {
        self.pipes.close(fd).map_err(Errno::from)
    }

    pub(crate) fn read_linux_pipe(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &mut [u8],
    ) -> Result<usize, Errno> {
        self.pipes.read(cx, fd, buf).map_err(Errno::from)
    }

    pub(crate) fn write_linux_pipe(
        &self,
        cx: &WaitContext<'_, Platform>,
        fd: &PipeFd<Platform>,
        buf: &[u8],
    ) -> Result<usize, Errno> {
        self.pipes.write(cx, fd, buf).map_err(Errno::from)
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
        self.pipes.set_status_flags(fd, mask, flags)?;
        Ok(())
    }

    pub(crate) fn linux_pipe_mode_bits(&self, fd: &PipeFd<Platform>) -> Result<u32, Errno> {
        let read_write_mode = match self.pipes.half_pipe_type(fd)? {
            HalfPipeType::SenderHalf => Mode::WUSR,
            HalfPipeType::ReceiverHalf => Mode::RUSR,
        };
        Ok(u32::from(read_write_mode.bits()) | InodeType::NamedPipe as u32)
    }

    /// Describes the pipe end at `fd` for a fresh runner inheriting it across `execve`.
    pub(crate) fn inherited_linux_pipe_kind(
        &self,
        fd: &PipeFd<Platform>,
    ) -> Result<InheritedFdKind, Errno> {
        Ok(InheritedFdKind::Pipe {
            endpoint: self.pipes.half_pipe_type(fd)?,
        })
    }

    /// Adopts a pipe end this runner inherited across `execve`.
    pub(crate) fn adopt_inherited_linux_pipe(
        &self,
        handle: ObjectHandle,
        endpoint_type: HalfPipeType,
    ) -> Result<PipeFd<Platform>, litebox::process::ProcessError> {
        self.litebox.adopt_inherited_pipe(handle, endpoint_type)
    }
}
